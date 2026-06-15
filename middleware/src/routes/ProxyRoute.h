#pragma once
#include <drogon/drogon.h>
#include <memory>
#include "../services/ProxyService.h"
#include "../repositories/BackendRepository.h"
#include "../services/SecurityClient.h"

class ProxyRoute : public drogon::HttpController<ProxyRoute> {
public:
    // Default constructor — Drogon requires this
    ProxyRoute() {
        auto dbClient       = drogon::app().getDbClient();
        auto repo           = std::make_shared<BackendRepository>(dbClient);
        auto engineUrl      = std::string(getenv("SECURITY_ENGINE_URL") 
                                ? getenv("SECURITY_ENGINE_URL") 
                                : "http://localhost:8081");
        auto securityClient = std::make_shared<SecurityClient>(engineUrl);
        proxyService_       = std::make_shared<ProxyService>(repo, securityClient);
    }

    METHOD_LIST_BEGIN
        ADD_METHOD_TO(ProxyRoute::handleRequest, "/proxy/{path}",
                      drogon::Get, drogon::Post, drogon::Put,
                      drogon::Delete, drogon::Patch);
    METHOD_LIST_END

    void handleRequest(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback,
        const std::string& path
    );

private:
    std::shared_ptr<ProxyService> proxyService_;

    std::string extractApiKey(const drogon::HttpRequestPtr& req);
};