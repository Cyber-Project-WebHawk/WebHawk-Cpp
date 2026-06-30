#include "JwtAuthFilter.h"
#include "../utils/JwtHelper.h"
#include <json/json.h>

void JwtAuthFilter::doFilter(const drogon::HttpRequestPtr& req,
                             drogon::FilterCallback&& fcb,
                             drogon::FilterChainCallback&& fccb) {
    auto unauthorized = [&fcb](const std::string& message) {
        Json::Value body;
        body["error"] = message;
        auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
        resp->setStatusCode(drogon::k401Unauthorized);
        fcb(resp);
    };

    const std::string authHeader = req->getHeader("authorization");
    const std::string prefix = "Bearer ";
    if (authHeader.size() <= prefix.size() ||
        authHeader.compare(0, prefix.size(), prefix) != 0) {
        unauthorized("Missing or malformed Authorization header");
        return;
    }

    const std::string token = authHeader.substr(prefix.size());
    const auto result = JwtHelper::verifyAccessToken(token);
    if (!result.valid) {
        unauthorized("Invalid or expired access token");
        return;
    }

    auto attrs = req->getAttributes();
    attrs->insert("user_id", result.userId);
    attrs->insert("user_email", result.email);
    attrs->insert("user_role", result.role);

    fccb();
}
