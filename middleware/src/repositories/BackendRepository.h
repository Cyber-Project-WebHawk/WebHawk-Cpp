#pragma once
#include <drogon/drogon.h>
#include <string>
#include <optional>
#include <functional>
#include <vector>

struct Backend {
    int id;
    std::string serviceName;
    std::string targetUrl;
    std::string apiKey;
    bool isActive;
};

class BackendRepository {
public:
    explicit BackendRepository(const drogon::orm::DbClientPtr& dbClient);

    void findByApiKey(
        const std::string& apiKey,
        std::function<void(std::optional<Backend>)>&& callback,
        std::function<void(const std::string&)>&& errorCallback
    );

    void save(
        const std::string& serviceName,
        const std::string& targetUrl,
        const std::string& apiKey,
        std::function<void(Backend)>&& callback,
        std::function<void(const std::string&)>&& errorCallback
    );

    // callback receives true if the backend was found and deactivated, false if not found.
    void deactivate(
        int id,
        std::function<void(bool)>&& callback,
        std::function<void(const std::string&)>&& errorCallback
    );

    void findAll(
        std::function<void(std::vector<Backend>)>&& callback,
        std::function<void(const std::string&)>&& errorCallback
    );

private:
    drogon::orm::DbClientPtr dbClient_;
};
