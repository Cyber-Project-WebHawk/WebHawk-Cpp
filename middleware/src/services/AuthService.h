#pragma once
#include <string>
#include <memory>
#include <functional>
#include "../repositories/UserRepository.h"
#include "../repositories/SessionRepository.h"

// Result returned to the caller after login/refresh.
struct AuthTokens {
    std::string accessToken;
    std::string refreshToken;
    int         userId = 0;
    std::string email;
    std::string role;
};

// Carries an HTTP status code plus a client-safe message.
struct AuthError {
    int         statusCode = 500;
    std::string message;
};

// Business logic for authentication. No HTTP, no raw SQL.
class AuthService {
public:
    // Brute-force protection thresholds.
    static constexpr int MAX_FAILED_ATTEMPTS   = 5;
    static constexpr int LOCK_DURATION_SECONDS = 15 * 60;

    AuthService(std::shared_ptr<UserRepository> users,
                std::shared_ptr<SessionRepository> sessions);

    void registerUser(
        const std::string& email,
        const std::string& password,
        std::function<void(User)>&& callback,
        std::function<void(AuthError)>&& errorCallback
    );

    void login(
        const std::string& email,
        const std::string& password,
        const std::string& ipAddress,
        const std::string& userAgent,
        std::function<void(AuthTokens)>&& callback,
        std::function<void(AuthError)>&& errorCallback
    );

    void refresh(
        const std::string& refreshToken,
        const std::string& ipAddress,
        const std::string& userAgent,
        std::function<void(AuthTokens)>&& callback,
        std::function<void(AuthError)>&& errorCallback
    );

    void logout(
        const std::string& refreshToken,
        std::function<void()>&& callback,
        std::function<void(AuthError)>&& errorCallback
    );

    void getCurrentUser(
        int userId,
        std::function<void(User)>&& callback,
        std::function<void(AuthError)>&& errorCallback
    );

private:
    std::shared_ptr<UserRepository>    users_;
    std::shared_ptr<SessionRepository> sessions_;

    // Issues an access + refresh token pair and persists the refresh session.
    void issueTokens(
        const User& user,
        const std::string& ipAddress,
        const std::string& userAgent,
        std::function<void(AuthTokens)>&& callback,
        std::function<void(AuthError)>&& errorCallback
    );

    // Validation helpers.
    static std::string normalizeEmail(const std::string& email);
    static bool isValidEmail(const std::string& email);
    static std::string validatePassword(const std::string& password); // "" = ok, else reason
};
