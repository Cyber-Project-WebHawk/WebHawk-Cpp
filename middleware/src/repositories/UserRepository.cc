#include "UserRepository.h"

UserRepository::UserRepository(const drogon::orm::DbClientPtr& dbClient)
    : dbClient_(dbClient) {}

// ── helpers ──────────────────────────────────────────────────────────────────

static User rowToUser(const drogon::orm::Row& row) {
    User u;
    u.id                  = row["id"].as<int>();
    u.email              = row["email"].as<std::string>();
    u.passwordHash       = row["password_hash"].as<std::string>();
    u.role               = row["role"].as<std::string>();
    u.failedLoginAttempts = row["failed_login_attempts"].as<int>();
    u.isLocked           = !row["is_locked"].isNull() && row["is_locked"].as<bool>();
    return u;
}

static const char* SELECT_COLUMNS =
    "id, email, password_hash, role, failed_login_attempts, "
    "(locked_until IS NOT NULL AND locked_until > NOW()) AS is_locked ";

// ── create ───────────────────────────────────────────────────────────────────

void UserRepository::create(
    const std::string& email,
    const std::string& passwordHash,
    const std::string& role,
    std::function<void(User)>&& callback,
    std::function<void(const std::string&)>&& errorCallback)
{
    dbClient_->execSqlAsync(
        "INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) "
        "RETURNING id, email, password_hash, role, failed_login_attempts, "
        "(locked_until IS NOT NULL AND locked_until > NOW()) AS is_locked",
        [callback = std::move(callback)](const drogon::orm::Result& result) {
            callback(rowToUser(result[0]));
        },
        [errorCallback = std::move(errorCallback)](const drogon::orm::DrogonDbException& e) {
            errorCallback(e.base().what());
        },
        email,
        passwordHash,
        role
    );
}

// ── countUsers ───────────────────────────────────────────────────────────────

void UserRepository::countUsers(
    std::function<void(int)>&& callback,
    std::function<void(const std::string&)>&& errorCallback)
{
    dbClient_->execSqlAsync(
        "SELECT COUNT(*) AS n FROM users",
        [callback = std::move(callback)](const drogon::orm::Result& result) {
            callback(result[0]["n"].as<int>());
        },
        [errorCallback = std::move(errorCallback)](const drogon::orm::DrogonDbException& e) {
            errorCallback(e.base().what());
        }
    );
}

// ── findByEmail ──────────────────────────────────────────────────────────────

void UserRepository::findByEmail(
    const std::string& email,
    std::function<void(std::optional<User>)>&& callback,
    std::function<void(const std::string&)>&& errorCallback)
{
    dbClient_->execSqlAsync(
        std::string("SELECT ") + SELECT_COLUMNS + "FROM users WHERE email = $1",
        [callback = std::move(callback)](const drogon::orm::Result& result) {
            if (result.empty()) {
                callback(std::nullopt);
            } else {
                callback(rowToUser(result[0]));
            }
        },
        [errorCallback = std::move(errorCallback)](const drogon::orm::DrogonDbException& e) {
            errorCallback(e.base().what());
        },
        email
    );
}

// ── findById ─────────────────────────────────────────────────────────────────

void UserRepository::findById(
    int id,
    std::function<void(std::optional<User>)>&& callback,
    std::function<void(const std::string&)>&& errorCallback)
{
    dbClient_->execSqlAsync(
        std::string("SELECT ") + SELECT_COLUMNS + "FROM users WHERE id = $1",
        [callback = std::move(callback)](const drogon::orm::Result& result) {
            if (result.empty()) {
                callback(std::nullopt);
            } else {
                callback(rowToUser(result[0]));
            }
        },
        [errorCallback = std::move(errorCallback)](const drogon::orm::DrogonDbException& e) {
            errorCallback(e.base().what());
        },
        id
    );
}

// ── recordFailedAttempt ──────────────────────────────────────────────────────

void UserRepository::recordFailedAttempt(
    int id,
    std::function<void(int)>&& callback,
    std::function<void(const std::string&)>&& errorCallback)
{
    dbClient_->execSqlAsync(
        "UPDATE users SET failed_login_attempts = failed_login_attempts + 1, "
        "updated_at = NOW() WHERE id = $1 RETURNING failed_login_attempts",
        [callback = std::move(callback)](const drogon::orm::Result& result) {
            callback(result[0]["failed_login_attempts"].as<int>());
        },
        [errorCallback = std::move(errorCallback)](const drogon::orm::DrogonDbException& e) {
            errorCallback(e.base().what());
        },
        id
    );
}

// ── lockAccount ──────────────────────────────────────────────────────────────

void UserRepository::lockAccount(
    int id,
    int lockSeconds,
    std::function<void()>&& callback,
    std::function<void(const std::string&)>&& errorCallback)
{
    dbClient_->execSqlAsync(
        "UPDATE users SET locked_until = NOW() + ($2::int * INTERVAL '1 second'), "
        "updated_at = NOW() WHERE id = $1",
        [callback = std::move(callback)](const drogon::orm::Result&) {
            callback();
        },
        [errorCallback = std::move(errorCallback)](const drogon::orm::DrogonDbException& e) {
            errorCallback(e.base().what());
        },
        id,
        lockSeconds
    );
}

// ── resetFailedAttempts ──────────────────────────────────────────────────────

void UserRepository::resetFailedAttempts(
    int id,
    std::function<void()>&& callback,
    std::function<void(const std::string&)>&& errorCallback)
{
    dbClient_->execSqlAsync(
        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, "
        "updated_at = NOW() WHERE id = $1",
        [callback = std::move(callback)](const drogon::orm::Result&) {
            callback();
        },
        [errorCallback = std::move(errorCallback)](const drogon::orm::DrogonDbException& e) {
            errorCallback(e.base().what());
        },
        id
    );
}
