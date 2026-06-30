#include "SessionRepository.h"

SessionRepository::SessionRepository(const drogon::orm::DbClientPtr& dbClient)
    : dbClient_(dbClient) {}

// ── create ───────────────────────────────────────────────────────────────────

void SessionRepository::create(
    int userId,
    const std::string& refreshTokenHash,
    const std::string& ipAddress,
    const std::string& userAgent,
    int expiresInSeconds,
    std::function<void()>&& callback,
    std::function<void(const std::string&)>&& errorCallback)
{
    dbClient_->execSqlAsync(
        "INSERT INTO user_sessions "
        "(user_id, refresh_token_hash, ip_address, user_agent, expires_at) "
        "VALUES ($1, $2, $3, $4, NOW() + ($5::int * INTERVAL '1 second'))",
        [callback = std::move(callback)](const drogon::orm::Result&) {
            callback();
        },
        [errorCallback = std::move(errorCallback)](const drogon::orm::DrogonDbException& e) {
            errorCallback(e.base().what());
        },
        userId,
        refreshTokenHash,
        ipAddress,
        userAgent,
        expiresInSeconds
    );
}

// ── findValidByHash ──────────────────────────────────────────────────────────

void SessionRepository::findValidByHash(
    const std::string& refreshTokenHash,
    std::function<void(std::optional<Session>)>&& callback,
    std::function<void(const std::string&)>&& errorCallback)
{
    dbClient_->execSqlAsync(
        "SELECT id, user_id FROM user_sessions "
        "WHERE refresh_token_hash = $1 AND is_active = TRUE "
        "AND revoked_at IS NULL AND expires_at > NOW()",
        [callback = std::move(callback)](const drogon::orm::Result& result) {
            if (result.empty()) {
                callback(std::nullopt);
            } else {
                Session s;
                s.id     = result[0]["id"].as<int>();
                s.userId = result[0]["user_id"].as<int>();
                callback(s);
            }
        },
        [errorCallback = std::move(errorCallback)](const drogon::orm::DrogonDbException& e) {
            errorCallback(e.base().what());
        },
        refreshTokenHash
    );
}

// ── revokeByHash ─────────────────────────────────────────────────────────────

void SessionRepository::revokeByHash(
    const std::string& refreshTokenHash,
    std::function<void()>&& callback,
    std::function<void(const std::string&)>&& errorCallback)
{
    dbClient_->execSqlAsync(
        "UPDATE user_sessions SET is_active = FALSE, revoked_at = NOW() "
        "WHERE refresh_token_hash = $1 AND is_active = TRUE",
        [callback = std::move(callback)](const drogon::orm::Result&) {
            callback();
        },
        [errorCallback = std::move(errorCallback)](const drogon::orm::DrogonDbException& e) {
            errorCallback(e.base().what());
        },
        refreshTokenHash
    );
}

// ── revokeAllForUser ─────────────────────────────────────────────────────────

void SessionRepository::revokeAllForUser(
    int userId,
    std::function<void()>&& callback,
    std::function<void(const std::string&)>&& errorCallback)
{
    dbClient_->execSqlAsync(
        "UPDATE user_sessions SET is_active = FALSE, revoked_at = NOW() "
        "WHERE user_id = $1 AND is_active = TRUE",
        [callback = std::move(callback)](const drogon::orm::Result&) {
            callback();
        },
        [errorCallback = std::move(errorCallback)](const drogon::orm::DrogonDbException& e) {
            errorCallback(e.base().what());
        },
        userId
    );
}
