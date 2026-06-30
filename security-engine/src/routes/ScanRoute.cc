#include "ScanRoute.h"
#include <map>
#include "../services/SqlInjectionDetector.h"
#include "../services/XssDetector.h"
#include "../services/RateLimiter.h"
#include "../repositories/SecurityLogRepository.h"

void ScanRoute::scan(const drogon::HttpRequestPtr& req,
                     std::function<void(const drogon::HttpResponsePtr&)>&& callback) {

    auto body = req->getJsonObject();
    if (!body) {
        Json::Value error;
        error["error"] = "Invalid JSON body";
        auto resp = drogon::HttpResponse::newHttpJsonResponse(error);
        resp->setStatusCode(drogon::k400BadRequest);
        callback(resp);
        return;
    }

    std::string ip          = (*body)["ip"].asString();
    std::string method      = (*body)["method"].asString();
    std::string path        = (*body)["path"].asString();
    std::string requestBody = (*body)["body"].asString();
    int         backendId   = (*body).get("backend_id", 0).asInt();

    std::map<std::string, std::string> queryParams;
    if (body->isMember("query_params")) {
        for (const auto& key : (*body)["query_params"].getMemberNames()) {
            queryParams[key] = (*body)["query_params"][key].asString();
        }
    }

    // Rate Limit check is async (Redis) — all subsequent checks run inside the callback.
    RateLimiter::checkBlocked(ip,
        [ip, method, path, requestBody, backendId,
         queryParams = std::move(queryParams),
         callback    = std::move(callback)](bool blocked) mutable {

            if (blocked) {
                SecurityLogRepository::log(backendId, ip, method, path, "RateLimit", requestBody);
                Json::Value result;
                result["safe"]        = false;
                result["attack_type"] = "RateLimit";
                result["detail"]      = "Too many requests from this IP";
                callback(drogon::HttpResponse::newHttpJsonResponse(result));
                return;
            }

            // SQL Injection check
            auto sqliResult = SqlInjectionDetector::scan(path, queryParams, requestBody);
            if (!sqliResult.safe) {
                SecurityLogRepository::log(backendId, ip, method, path, "SQLi", requestBody);
                Json::Value result;
                result["safe"]        = false;
                result["attack_type"] = "SQLi";
                result["detail"]      = sqliResult.detail;
                callback(drogon::HttpResponse::newHttpJsonResponse(result));
                return;
            }

            // XSS check (now also scans path)
            auto xssResult = XssDetector::scan(path, queryParams, requestBody);
            if (!xssResult.safe) {
                SecurityLogRepository::log(backendId, ip, method, path, "XSS", requestBody);
                Json::Value result;
                result["safe"]        = false;
                result["attack_type"] = "XSS";
                result["detail"]      = xssResult.detail;
                callback(drogon::HttpResponse::newHttpJsonResponse(result));
                return;
            }

            // All checks passed
            Json::Value result;
            result["safe"]        = true;
            result["attack_type"] = "";
            result["detail"]      = "";
            callback(drogon::HttpResponse::newHttpJsonResponse(result));
        }
    );
}
