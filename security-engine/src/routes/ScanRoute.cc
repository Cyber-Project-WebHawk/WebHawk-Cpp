#include "ScanRoute.h"
#include <map>
#include "../services/SqlInjectionDetector.h"
#include "../services/XssDetector.h"
#include "../services/RateLimiter.h"
#include "../repositories/SecurityLogRepository.h"

void ScanRoute::scan(const drogon::HttpRequestPtr& req,
                     std::function<void(const drogon::HttpResponsePtr&)>&& callback) {

    // Parse the JSON body sent by the middleware
    auto body = req->getJsonObject();
    if (!body) {
        Json::Value error;
        error["error"] = "Invalid JSON body";
        auto resp = drogon::HttpResponse::newHttpJsonResponse(error);
        resp->setStatusCode(drogon::k400BadRequest);
        callback(resp);
        return;
    }

    // Extract fields from the request
    std::string ip          = (*body)["ip"].asString();
    std::string method      = (*body)["method"].asString();
    std::string path        = (*body)["path"].asString();
    std::string requestBody = (*body)["body"].asString();

    // Extract query params into a map
    std::map<std::string, std::string> queryParams;
    if (body->isMember("queryParams")) {
        for (const auto& key : (*body)["queryParams"].getMemberNames()) {
            queryParams[key] = (*body)["queryParams"][key].asString();
        }
    }

    // Run Rate Limiter first (cheapest check — just a Redis counter)
    if (RateLimiter::isBlocked(ip)) {
        SecurityLogRepository::log(ip, method, path, "RateLimit", requestBody);
        Json::Value result;
        result["safe"]       = false;
        result["attackType"] = "RateLimit";
        result["detail"]     = "Too many requests from this IP";
        callback(drogon::HttpResponse::newHttpJsonResponse(result));
        return;
    }

    // Run SQL Injection detector
    auto sqliResult = SqlInjectionDetector::scan(path, queryParams, requestBody);
    if (!sqliResult.safe) {
        SecurityLogRepository::log(ip, method, path, "SQLi", requestBody);
        Json::Value result;
        result["safe"]       = false;
        result["attackType"] = "SQLi";
        result["detail"]     = sqliResult.detail;
        callback(drogon::HttpResponse::newHttpJsonResponse(result));
        return;
    }

    // Run XSS detector
    auto xssResult = XssDetector::scan(queryParams, requestBody);
    if (!xssResult.safe) {
        SecurityLogRepository::log(ip, method, path, "XSS", requestBody);
        Json::Value result;
        result["safe"]       = false;
        result["attackType"] = "XSS";
        result["detail"]     = xssResult.detail;
        callback(drogon::HttpResponse::newHttpJsonResponse(result));
        return;
    }

    // All checks passed — request is safe
    Json::Value result;
    result["safe"]       = true;
    result["attackType"] = "";
    result["detail"]     = "";
    callback(drogon::HttpResponse::newHttpJsonResponse(result));
}
