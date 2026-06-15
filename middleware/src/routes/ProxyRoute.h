#pragma once
#include <drogon/drogon.h>
#include <memory>
#include "../services/ProxyService.h"

// Catches ALL incoming requests under /proxy/*
class ProxyRoute : public drogon::HttpController<ProxyRoute> {
public:
    explicit ProxyRoute(std::shared_ptr<ProxyService> proxyService);

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

    // Extracts X-WebHawk-API-Key from headers, returns "" if missing
    std::string extractApiKey(const drogon::HttpRequestPtr& req);
};
