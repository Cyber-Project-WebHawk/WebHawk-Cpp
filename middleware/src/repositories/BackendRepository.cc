#include "BackendRepository.h"

BackendRepository::BackendRepository(const drogon::orm::DbClientPtr& dbClient)
    : dbClient_(dbClient) {}

// ── helpers ──────────────────────────────────────────────────────────────────

static Backend rowToBackend(const drogon::orm::Row& row) {
    Backend b;
    b.id          = row["id"].as<int>();
    b.serviceName = row["service_name"].as<std::string>();
    b.targetUrl   = row["target_url"].as<std::string>();
    b.apiKey      = row["api_key"].as<std::string>();
    b.isActive    = row["is_active"].as<bool>();
    return b;
}

// ── findByApiKey ──────────────────────────────────────────────────────────────

void BackendRepository::findByApiKey(
    const std::string& apiKey,
    std::function<void(std::optional<Backend>)>&& callback,
    std::function<void(const std::string&)>&& errorCallback)
{
    dbClient_->execSqlAsync(
        "SELECT id, service_name, target_url, api_key, is_active "
        "FROM backend_registration "
        "WHERE api_key = $1 AND is_active = TRUE",
        [callback = std::move(callback)](const drogon::orm::Result& result) {
            if (result.empty()) {
                callback(std::nullopt);
            } else {
                callback(rowToBackend(result[0]));
            }
        },
        [errorCallback = std::move(errorCallback)](const drogon::orm::DrogonDbException& e) {
            errorCallback(e.base().what());
        },
        apiKey
    );
}

// ── save ─────────────────────────────────────────────────────────────────────

void BackendRepository::save(
    const std::string& serviceName,
    const std::string& targetUrl,
    const std::string& apiKey,
    std::function<void(Backend)>&& callback,
    std::function<void(const std::string&)>&& errorCallback)
{
    dbClient_->execSqlAsync(
        "INSERT INTO backend_registration (service_name, target_url, api_key) "
        "VALUES ($1, $2, $3) "
        "RETURNING id, service_name, target_url, api_key, is_active",
        [callback = std::move(callback)](const drogon::orm::Result& result) {
            callback(rowToBackend(result[0]));
        },
        [errorCallback = std::move(errorCallback)](const drogon::orm::DrogonDbException& e) {
            errorCallback(e.base().what());
        },
        serviceName,
        targetUrl,
        apiKey
    );
}

// ── deactivate ────────────────────────────────────────────────────────────────

void BackendRepository::deactivate(
    int id,
    std::function<void()>&& callback,
    std::function<void(const std::string&)>&& errorCallback)
{
    dbClient_->execSqlAsync(
        "UPDATE backend_registration SET is_active = FALSE WHERE id = $1",
        [callback = std::move(callback)](const drogon::orm::Result& /*result*/) {
            callback();
        },
        [errorCallback = std::move(errorCallback)](const drogon::orm::DrogonDbException& e) {
            errorCallback(e.base().what());
        },
        id
    );
}

// ── findAll ───────────────────────────────────────────────────────────────────

void BackendRepository::findAll(
    std::function<void(std::vector<Backend>)>&& callback,
    std::function<void(const std::string&)>&& errorCallback)
{
    dbClient_->execSqlAsync(
        "SELECT id, service_name, target_url, api_key, is_active "
        "FROM backend_registration "
        "ORDER BY id ASC",
        [callback = std::move(callback)](const drogon::orm::Result& result) {
            std::vector<Backend> backends;
            backends.reserve(result.size());
            for (const auto& row : result) {
                backends.push_back(rowToBackend(row));
            }
            callback(std::move(backends));
        },
        [errorCallback = std::move(errorCallback)](const drogon::orm::DrogonDbException& e) {
            errorCallback(e.base().what());
        }
    );
}
