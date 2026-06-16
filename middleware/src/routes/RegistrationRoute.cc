#include "RegistrationRoute.h"
#include <json/json.h>

// ── POST /api/backends/register ───────────────────────────────────────────────

void RegistrationRoute::registerBackend(
    const drogon::HttpRequestPtr& req,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback)
{
    auto json = req->getJsonObject();
    if (!json || !(*json)["serviceName"].isString() || !(*json)["targetUrl"].isString()) {
        Json::Value err;
        err["error"] = "Request body must contain 'serviceName' and 'targetUrl'";
        auto resp = drogon::HttpResponse::newHttpJsonResponse(err);
        resp->setStatusCode(drogon::k400BadRequest);
        callback(resp);
        return;
    }

    RegistrationRequest request;
    request.serviceName = (*json)["serviceName"].asString();
    request.targetUrl   = (*json)["targetUrl"].asString();

    if (request.serviceName.empty() || request.targetUrl.empty()) {
        Json::Value err;
        err["error"] = "'serviceName' and 'targetUrl' must not be empty";
        auto resp = drogon::HttpResponse::newHttpJsonResponse(err);
        resp->setStatusCode(drogon::k400BadRequest);
        callback(resp);
        return;
    }

    getService()->registerBackend(
        request,
        [callback](RegistrationResult result) {
            Json::Value body;
            body["id"]          = result.backend.id;
            body["serviceName"] = result.backend.serviceName;
            body["targetUrl"]   = result.backend.targetUrl;
            body["apiKey"]      = result.apiKey;
            body["isActive"]    = result.backend.isActive;
            auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
            resp->setStatusCode(drogon::k201Created);
            callback(resp);
        },
        [callback](const std::string& err) {
            Json::Value body;
            body["error"] = err;
            auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
            resp->setStatusCode(drogon::k500InternalServerError);
            callback(resp);
        }
    );
}

// ── GET /api/backends ─────────────────────────────────────────────────────────

void RegistrationRoute::listBackends(
    const drogon::HttpRequestPtr& req,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback)
{
    getService()->listBackends(
        [callback](std::vector<Backend> backends) {
            Json::Value arr(Json::arrayValue);
            for (const auto& b : backends) {
                Json::Value item;
                item["id"]          = b.id;
                item["serviceName"] = b.serviceName;
                item["targetUrl"]   = b.targetUrl;
                item["isActive"]    = b.isActive;
                arr.append(item);
            }
            auto resp = drogon::HttpResponse::newHttpJsonResponse(arr);
            resp->setStatusCode(drogon::k200OK);
            callback(resp);
        },
        [callback](const std::string& err) {
            Json::Value body;
            body["error"] = err;
            auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
            resp->setStatusCode(drogon::k500InternalServerError);
            callback(resp);
        }
    );
}

// ── DELETE /api/backends/{id} ─────────────────────────────────────────────────

void RegistrationRoute::deactivateBackend(
    const drogon::HttpRequestPtr& req,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback,
    int id)
{
    if (id <= 0) {
        Json::Value err;
        err["error"] = "Invalid id";
        auto resp = drogon::HttpResponse::newHttpJsonResponse(err);
        resp->setStatusCode(drogon::k400BadRequest);
        callback(resp);
        return;
    }

    getService()->deactivateBackend(
        id,
        [callback]() {
            auto resp = drogon::HttpResponse::newHttpResponse();
            resp->setStatusCode(drogon::k204NoContent);
            callback(resp);
        },
        [callback](const std::string& err) {
            Json::Value body;
            body["error"] = err;
            auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
            resp->setStatusCode(drogon::k500InternalServerError);
            callback(resp);
        }
    );
}