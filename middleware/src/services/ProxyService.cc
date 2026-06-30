#include "ProxyService.h"
#include <json/json.h>

ProxyService::ProxyService(
    std::shared_ptr<BackendRepository> repo,
    std::shared_ptr<SecurityClient> securityClient)
    : repo_(std::move(repo))
    , securityClient_(std::move(securityClient)) {}

void ProxyService::handleRequest(
    const drogon::HttpRequestPtr& req,
    const std::string& apiKey,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback)
{
    repo_->findByApiKey(
        apiKey,
        [this, req, callback = std::move(callback)]
        (std::optional<Backend> backend) mutable {
            if (!backend) {
                Json::Value body;
                body["error"] = "Unknown API key";
                auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
                resp->setStatusCode(drogon::k404NotFound);
                callback(resp);
                return;
            }

            ScanRequest scanReq;
            scanReq.backendId = backend->id;
            scanReq.ip        = req->getPeerAddr().toIp();
            scanReq.method    = req->getMethodString();
            scanReq.path      = req->getPath();
            scanReq.body      = std::string(req->getBody());

            for (const auto& [k, v] : req->getParameters()) {
                scanReq.queryParams[k] = v;
            }
            for (const auto& [k, v] : req->getHeaders()) {
                scanReq.headers[k] = v;
            }

            const std::string targetUrl = backend->targetUrl;

            securityClient_->scan(
                scanReq,
                [this, req, targetUrl, callback = std::move(callback)]
                (ScanResult result) mutable {
                    if (!result.safe) {
                        callback(makeBlockedResponse(result.attackType));
                        return;
                    }
                    forwardRequest(req, targetUrl, std::move(callback));
                },
                [callback](const std::string& err) mutable {
                    Json::Value body;
                    body["error"] = "Security scan unavailable: " + err;
                    auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
                    resp->setStatusCode(drogon::k503ServiceUnavailable);
                    callback(resp);
                }
            );
        },
        [callback](const std::string& err) mutable {
            Json::Value body;
            body["error"] = "Database error: " + err;
            auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
            resp->setStatusCode(drogon::k500InternalServerError);
            callback(resp);
        }
    );
}

void ProxyService::forwardRequest(
    const drogon::HttpRequestPtr& req,
    const std::string& targetUrl,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback)
{
    req->removeHeader("x-webhawk-api-key");

    std::string forwardPath = req->getPath();
    const std::string proxyPrefix = "/proxy";
    if (forwardPath.substr(0, proxyPrefix.size()) == proxyPrefix) {
        forwardPath = forwardPath.substr(proxyPrefix.size());
    }
    if (forwardPath.empty()) forwardPath = "/";
    req->setPath(forwardPath);

    auto client = drogon::HttpClient::newHttpClient(targetUrl);
    client->sendRequest(
        req,
        [callback = std::move(callback)]
        (drogon::ReqResult result, const drogon::HttpResponsePtr& resp) {
            if (result == drogon::ReqResult::Ok && resp) {
                resp->removeHeader("content-length");
                resp->removeHeader("transfer-encoding");
                callback(resp);
            } else {
                auto err = drogon::HttpResponse::newHttpResponse();
                err->setStatusCode(drogon::k502BadGateway);
                err->setBody(R"({"error":"Backend unreachable"})");
                err->setContentTypeCode(drogon::CT_APPLICATION_JSON);
                callback(err);
            }
        });
}

drogon::HttpResponsePtr ProxyService::makeBlockedResponse(const std::string& attackType)
{
    Json::Value body;
    body["error"]       = "Blocked by WebHawk";
    body["attack_type"] = attackType;
    auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
    resp->setStatusCode(drogon::k403Forbidden);
    return resp;
}