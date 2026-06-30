#include "AuthService.h"
#include "../utils/PasswordHasher.h"
#include "../utils/JwtHelper.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <regex>

AuthService::AuthService(std::shared_ptr<UserRepository> users,
                         std::shared_ptr<SessionRepository> sessions)
    : users_(std::move(users))
    , sessions_(std::move(sessions)) {}

// ── validation helpers ───────────────────────────────────────────────────────

std::string AuthService::normalizeEmail(const std::string& email) {
    std::string out = email;
    // trim surrounding whitespace
    auto notSpace = [](unsigned char c) { return !std::isspace(c); };
    out.erase(out.begin(), std::find_if(out.begin(), out.end(), notSpace));
    out.erase(std::find_if(out.rbegin(), out.rend(), notSpace).base(), out.end());
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return out;
}

bool AuthService::isValidEmail(const std::string& email) {
    // Pragmatic RFC-5322-ish check; good enough to reject malformed input.
    static const std::regex re(R"(^[^@\s]+@[^@\s]+\.[^@\s]+$)");
    return email.size() <= 255 && std::regex_match(email, re);
}

std::string AuthService::validatePassword(const std::string& password) {
    if (password.size() < 8) {
        return "Password must be at least 8 characters long";
    }
    if (password.size() > 256) {
        return "Password must be at most 256 characters long";
    }
    const bool hasLetter = std::any_of(password.begin(), password.end(),
                                       [](unsigned char c) { return std::isalpha(c); });
    const bool hasDigit  = std::any_of(password.begin(), password.end(),
                                       [](unsigned char c) { return std::isdigit(c); });
    if (!hasLetter || !hasDigit) {
        return "Password must contain at least one letter and one digit";
    }
    return "";
}

// ── registerUser ─────────────────────────────────────────────────────────────

void AuthService::registerUser(
    const std::string& email,
    const std::string& password,
    std::function<void(User)>&& callback,
    std::function<void(AuthError)>&& errorCallback)
{
    const std::string normEmail = normalizeEmail(email);

    if (!isValidEmail(normEmail)) {
        errorCallback({400, "A valid email address is required"});
        return;
    }
    if (const std::string reason = validatePassword(password); !reason.empty()) {
        errorCallback({400, reason});
        return;
    }

    users_->findByEmail(
        normEmail,
        [this, normEmail, password,
         callback = std::move(callback),
         errorCallback](std::optional<User> existing) mutable {
            if (existing) {
                errorCallback({409, "Email is already registered"});
                return;
            }

            std::string hash;
            try {
                hash = PasswordHasher::hash(password);
            } catch (const std::exception& e) {
                errorCallback({500, std::string("Failed to hash password: ") + e.what()});
                return;
            }

            // Bootstrap: the very first registered user becomes the admin so the
            // system is usable out of the box; everyone else is a normal user.
            users_->countUsers(
                [this, normEmail, hash,
                 callback = std::move(callback), errorCallback](int count) mutable {
                    const std::string role = (count == 0) ? "admin" : "user";
                    users_->create(
                        normEmail,
                        hash,
                        role,
                        [callback = std::move(callback)](User user) {
                            callback(std::move(user));
                        },
                        [errorCallback](const std::string& err) {
                            errorCallback({500, std::string("Failed to create user: ") + err});
                        }
                    );
                },
                [errorCallback](const std::string& err) {
                    errorCallback({500, std::string("Database error: ") + err});
                }
            );
        },
        [errorCallback](const std::string& err) {
            errorCallback({500, std::string("Database error: ") + err});
        }
    );
}

// ── login ────────────────────────────────────────────────────────────────────

void AuthService::login(
    const std::string& email,
    const std::string& password,
    const std::string& ipAddress,
    const std::string& userAgent,
    std::function<void(AuthTokens)>&& callback,
    std::function<void(AuthError)>&& errorCallback)
{
    const std::string normEmail = normalizeEmail(email);

    users_->findByEmail(
        normEmail,
        [this, password, ipAddress, userAgent,
         callback = std::move(callback),
         errorCallback](std::optional<User> maybeUser) mutable {
            // Generic message — never reveal whether the email exists.
            const AuthError invalidCreds{401, "Invalid email or password"};

            if (!maybeUser) {
                // Equalize timing against the password-verify path for real users.
                static const std::string dummyHash = PasswordHasher::hash("timing-equalizer");
                (void)PasswordHasher::verify(password, dummyHash);
                errorCallback(invalidCreds);
                return;
            }

            User user = *maybeUser;

            if (user.isLocked) {
                errorCallback({429, "Account temporarily locked due to too many failed login attempts. Try again later."});
                return;
            }

            if (!PasswordHasher::verify(password, user.passwordHash)) {
                users_->recordFailedAttempt(
                    user.id,
                    [this, user, errorCallback, invalidCreds](int newCount) {
                        if (newCount >= MAX_FAILED_ATTEMPTS) {
                            users_->lockAccount(
                                user.id, LOCK_DURATION_SECONDS,
                                [errorCallback]() {
                                    errorCallback({429, "Account temporarily locked due to too many failed login attempts. Try again later."});
                                },
                                [errorCallback](const std::string&) {
                                    errorCallback({401, "Invalid email or password"});
                                }
                            );
                        } else {
                            errorCallback(invalidCreds);
                        }
                    },
                    [errorCallback, invalidCreds](const std::string&) {
                        errorCallback(invalidCreds);
                    }
                );
                return;
            }

            // Success: clear counters, then issue tokens.
            users_->resetFailedAttempts(
                user.id,
                [this, user, ipAddress, userAgent,
                 callback = std::move(callback), errorCallback]() mutable {
                    issueTokens(user, ipAddress, userAgent,
                                std::move(callback), std::move(errorCallback));
                },
                [errorCallback](const std::string& err) {
                    errorCallback({500, std::string("Database error: ") + err});
                }
            );
        },
        [errorCallback](const std::string& err) {
            errorCallback({500, std::string("Database error: ") + err});
        }
    );
}

// ── refresh ──────────────────────────────────────────────────────────────────

void AuthService::refresh(
    const std::string& refreshToken,
    const std::string& ipAddress,
    const std::string& userAgent,
    std::function<void(AuthTokens)>&& callback,
    std::function<void(AuthError)>&& errorCallback)
{
    std::string hash;
    try {
        hash = JwtHelper::sha256Hex(refreshToken);
    } catch (const std::exception& e) {
        errorCallback({500, std::string("Token error: ") + e.what()});
        return;
    }

    sessions_->findValidByHash(
        hash,
        [this, hash, ipAddress, userAgent,
         callback = std::move(callback),
         errorCallback](std::optional<Session> session) mutable {
            if (!session) {
                errorCallback({401, "Invalid or expired refresh token"});
                return;
            }

            const int userId = session->userId;

            // Rotate: revoke the presented refresh token before issuing a new one.
            sessions_->revokeByHash(
                hash,
                [this, userId, ipAddress, userAgent,
                 callback = std::move(callback), errorCallback]() mutable {
                    users_->findById(
                        userId,
                        [this, ipAddress, userAgent,
                         callback = std::move(callback),
                         errorCallback](std::optional<User> maybeUser) mutable {
                            if (!maybeUser) {
                                errorCallback({401, "Invalid or expired refresh token"});
                                return;
                            }
                            issueTokens(*maybeUser, ipAddress, userAgent,
                                        std::move(callback), std::move(errorCallback));
                        },
                        [errorCallback](const std::string& err) {
                            errorCallback({500, std::string("Database error: ") + err});
                        }
                    );
                },
                [errorCallback](const std::string& err) {
                    errorCallback({500, std::string("Database error: ") + err});
                }
            );
        },
        [errorCallback](const std::string& err) {
            errorCallback({500, std::string("Database error: ") + err});
        }
    );
}

// ── logout ───────────────────────────────────────────────────────────────────

void AuthService::logout(
    const std::string& refreshToken,
    std::function<void()>&& callback,
    std::function<void(AuthError)>&& errorCallback)
{
    std::string hash;
    try {
        hash = JwtHelper::sha256Hex(refreshToken);
    } catch (const std::exception& e) {
        errorCallback({500, std::string("Token error: ") + e.what()});
        return;
    }

    // Idempotent: revoking an unknown/already-revoked token still succeeds.
    sessions_->revokeByHash(
        hash,
        [callback = std::move(callback)]() { callback(); },
        [errorCallback](const std::string& err) {
            errorCallback({500, std::string("Database error: ") + err});
        }
    );
}

// ── getCurrentUser ───────────────────────────────────────────────────────────

void AuthService::getCurrentUser(
    int userId,
    std::function<void(User)>&& callback,
    std::function<void(AuthError)>&& errorCallback)
{
    users_->findById(
        userId,
        [callback = std::move(callback), errorCallback](std::optional<User> maybeUser) {
            if (!maybeUser) {
                errorCallback({404, "User not found"});
                return;
            }
            callback(std::move(*maybeUser));
        },
        [errorCallback](const std::string& err) {
            errorCallback({500, std::string("Database error: ") + err});
        }
    );
}

// ── issueTokens ──────────────────────────────────────────────────────────────

void AuthService::issueTokens(
    const User& user,
    const std::string& ipAddress,
    const std::string& userAgent,
    std::function<void(AuthTokens)>&& callback,
    std::function<void(AuthError)>&& errorCallback)
{
    AuthTokens tokens;
    std::string refreshHash;
    try {
        tokens.accessToken  = JwtHelper::createAccessToken(user.id, user.email, user.role);
        tokens.refreshToken = JwtHelper::generateRefreshToken();
        tokens.userId       = user.id;
        tokens.email        = user.email;
        tokens.role         = user.role;
        refreshHash         = JwtHelper::sha256Hex(tokens.refreshToken);
    } catch (const std::exception& e) {
        errorCallback({500, std::string("Failed to issue tokens: ") + e.what()});
        return;
    }

    const int refreshTtlSeconds = static_cast<int>(
        std::chrono::duration_cast<std::chrono::seconds>(JwtHelper::REFRESH_TOKEN_TTL).count());

    sessions_->create(
        user.id,
        refreshHash,
        ipAddress,
        userAgent,
        refreshTtlSeconds,
        [tokens = std::move(tokens), callback = std::move(callback)]() mutable {
            callback(std::move(tokens));
        },
        [errorCallback](const std::string& err) {
            errorCallback({500, std::string("Failed to persist session: ") + err});
        }
    );
}
