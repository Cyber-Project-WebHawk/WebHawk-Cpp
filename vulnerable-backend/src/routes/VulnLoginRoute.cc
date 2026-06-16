// INTENTIONALLY VULNERABLE — FOR TESTING WEBHAWK ONLY
// DO NOT USE IN PRODUCTION
// Vulnerability: username is concatenated raw into SQL → SQL Injection

#include "VulnLoginRoute.h"
#include <json/json.h>

void VulnLoginRoute::login(
    const drogon::HttpRequestPtr& req,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback)
{
    std::string username;
    std::string password;

    // Try JSON body first
    auto body_json = req->getJsonObject();
    if (body_json && !body_json->isNull()) {
        if ((*body_json).isMember("username"))
            username = (*body_json)["username"].asString();
        if ((*body_json).isMember("password"))
            password = (*body_json)["password"].asString();
    }

    // Fall back to form/query params
    if (username.empty()) {
        auto params = req->getParameters();
        username = params.count("username") ? params.at("username") : "";
        password = params.count("password") ? params.at("password") : "";
    }

    if (username.empty()) {
        Json::Value err;
        err["error"] = "username is required";
        auto resp = drogon::HttpResponse::newHttpJsonResponse(err);
        resp->setStatusCode(drogon::k400BadRequest);
        callback(resp);
        return;
    }

    // INTENTIONAL VULNERABILITY: raw string concatenation — no parameterised query
    const std::string vuln_sql =
        "SELECT id, username FROM users WHERE username = '" + username +
        "' AND password_hash = '" + password + "'";

    auto db = drogon::app().getDbClient();
    db->execSqlAsync(
        vuln_sql,
        [callback](const drogon::orm::Result& result) {
            Json::Value resp_body;
            if (result.size() > 0) {
                resp_body["success"]  = true;
                resp_body["message"]  = "Login successful";
                resp_body["user_id"]  = result[0]["id"].as<int>();
                resp_body["username"] = result[0]["username"].as<std::string>();
                auto resp = drogon::HttpResponse::newHttpJsonResponse(resp_body);
                resp->setStatusCode(drogon::k200OK);
                callback(resp);
            } else {
                resp_body["success"] = false;
                resp_body["message"] = "Invalid credentials";
                auto resp = drogon::HttpResponse::newHttpJsonResponse(resp_body);
                resp->setStatusCode(drogon::k401Unauthorized);
                callback(resp);
            }
        },
        [callback](const drogon::orm::DrogonDbException& e) {
            Json::Value resp_body;
            resp_body["error"]   = std::string(e.base().what());
            resp_body["message"] = "DB error — your SQL injection may have worked!";
            auto resp = drogon::HttpResponse::newHttpJsonResponse(resp_body);
            resp->setStatusCode(drogon::k500InternalServerError);
            callback(resp);
        });
}