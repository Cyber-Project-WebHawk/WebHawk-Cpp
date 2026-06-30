#pragma once
#include <string>
#include <chrono>

// Stateless JWT (HS256) access tokens plus helpers for opaque refresh tokens.
//
// Access tokens are signed JWTs carrying user identity and role; they are never
// stored server-side. Refresh tokens are high-entropy opaque strings — only their
// SHA-256 hash is persisted (see SessionRepository), enabling revocation/rotation.
class JwtHelper {
public:
    // Lifetimes (single source of truth, also used by repositories/services).
    static constexpr std::chrono::minutes ACCESS_TOKEN_TTL{15};
    static constexpr std::chrono::hours   REFRESH_TOKEN_TTL{24 * 7};

    struct AccessToken {
        int         userId = 0;
        std::string email;
        std::string role;
        bool        valid = false;
    };

    // Creates a signed access JWT (claims: sub, email, role, type="access").
    static std::string createAccessToken(int userId,
                                         const std::string& email,
                                         const std::string& role);

    // Verifies signature, issuer, expiry and type=="access". Returns valid=false on any failure.
    static AccessToken verifyAccessToken(const std::string& token);

    // Generates a cryptographically-random opaque refresh token (64 hex chars).
    static std::string generateRefreshToken();

    // SHA-256 hex digest, used to store/lookup refresh tokens without keeping plaintext.
    static std::string sha256Hex(const std::string& input);

private:
    // Reads JWT_SECRET from the environment once (throws if unset/empty).
    static const std::string& secret();

    JwtHelper() = delete;
};
