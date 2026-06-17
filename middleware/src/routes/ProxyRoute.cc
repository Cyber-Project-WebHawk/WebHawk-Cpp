#include "ProxyRoute.h"
#include <json/json.h>

void ProxyRoute::handleRequest(
    const drogon::HttpRequestPtr& req,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback,
    const std::string& path)
{
    const std::string apiKey = extractApiKey(req);

    if (apiKey.empty()) {
        Json::Value body;
        body["error"] = "Missing X-WebHawk-API-Key header";
        auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
        resp->setStatusCode(drogon::k401Unauthorized);
        callback(resp);
        return;
    }

    getProxyService()->handleRequest(req, apiKey, std::move(callback));
}

std::string ProxyRoute::extractApiKey(const drogon::HttpRequestPtr& req)
{
    const auto& headers = req->getHeaders();
    auto it = headers.find("x-webhawk-api-key");
    if (it == headers.end()) {
        return "";
    }
    return it->second;
}