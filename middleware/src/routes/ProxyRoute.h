#pragma once
#include <drogon/drogon.h>
#include <memory>
#include <mutex>
#include "../services/ProxyService.h"
#include "../repositories/BackendRepository.h"
#include "../services/SecurityClient.h"

class ProxyRoute : public drogon::HttpController<ProxyRoute> {
public:
    METHOD_LIST_BEGIN
        ADD_METHOD_VIA_REGEX(ProxyRoute::handleRequest, "/proxy/(.*)",
                             drogon::Get, drogon::Post, drogon::Put,
                             drogon::Delete, drogon::Patch);
    METHOD_LIST_END

    void handleRequest(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback,
        const std::string& path
    );

private:
    std::shared_ptr<ProxyService> getProxyService() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!proxyService_) {
            auto db        = drogon::app().getDbClient();
            auto repo      = std::make_shared<BackendRepository>(db);
            const std::string url = getenv("SECURITY_ENGINE_URL")
                                    ? getenv("SECURITY_ENGINE_URL")
                                    : "http://localhost:8081";
            auto secClient = std::make_shared<SecurityClient>(url);
            proxyService_  = std::make_shared<ProxyService>(repo, secClient);
        }
        return proxyService_;
    }

    std::shared_ptr<ProxyService> proxyService_;
    std::mutex mutex_;
    std::string extractApiKey(const drogon::HttpRequestPtr& req);
};