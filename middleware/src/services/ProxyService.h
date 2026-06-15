#pragma once
#include <drogon/drogon.h>
#include <memory>
#include <functional>
#include "../repositories/BackendRepository.h"
#include "SecurityClient.h"

class ProxyService {
public:
    ProxyService(
        std::shared_ptr<BackendRepository> repo,
        std::shared_ptr<SecurityClient> securityClient
    );

    // Main proxy logic:
    // 1. Lookup backend by API key
    // 2. Scan request with security engine
    // 3. Forward if safe, block if malicious
    void handleRequest(
        const drogon::HttpRequestPtr& req,
        const std::string& apiKey,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback
    );

private:
    std::shared_ptr<BackendRepository> repo_;
    std::shared_ptr<SecurityClient> securityClient_;

    void forwardRequest(
        const drogon::HttpRequestPtr& req,
        const std::string& targetUrl,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback
    );

    drogon::HttpResponsePtr makeBlockedResponse(const std::string& attackType);
};
