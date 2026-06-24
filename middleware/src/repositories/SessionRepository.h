#pragma once
#include <drogon/drogon.h>
#include <string>
#include <optional>
#include <functional>

struct Session {
    int id = 0;
    int userId = 0;
};

// Database access for the `user_sessions` table (refresh-token store).
// Only SHA-256 hashes of refresh tokens are ever persisted.
class SessionRepository {
public:
    explicit SessionRepository(const drogon::orm::DbClientPtr& dbClient);

    void create(
        int userId,
        const std::string& refreshTokenHash,
        const std::string& ipAddress,
        const std::string& userAgent,
        int expiresInSeconds,
        std::function<void()>&& callback,
        std::function<void(const std::string&)>&& errorCallback
    );

    // Returns the session only if active, not revoked and not expired.
    void findValidByHash(
        const std::string& refreshTokenHash,
        std::function<void(std::optional<Session>)>&& callback,
        std::function<void(const std::string&)>&& errorCallback
    );

    // Revokes a single session by its refresh-token hash (logout).
    void revokeByHash(
        const std::string& refreshTokenHash,
        std::function<void()>&& callback,
        std::function<void(const std::string&)>&& errorCallback
    );

    // Revokes every active session for a user (logout everywhere / password change).
    void revokeAllForUser(
        int userId,
        std::function<void()>&& callback,
        std::function<void(const std::string&)>&& errorCallback
    );

private:
    drogon::orm::DbClientPtr dbClient_;
};
