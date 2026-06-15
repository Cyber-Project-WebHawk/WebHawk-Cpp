// INTENTIONALLY VULNERABLE — FOR TESTING WEBHAWK ONLY
// DO NOT USE IN PRODUCTION
// Vulnerability: username is concatenated raw into the SQL query → SQL Injection

#include "VulnLoginRoute.h"
#include <json/json.h>

void VulnLoginRoute::login(
    const drogon::HttpRequestPtr& req,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback)
{
    auto body_json = req->getJsonObject();

    std::string username;
    std::string password;

    if (body_json) {
        username = (*body_json)["username"].asString();
        password = (*body_json)["password"].asString();
    } else {
        auto params  = req->getParameters();
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
    // A payload like:  ' OR '1'='1  bypasses authentication entirely
    const std::string vuln_sql =
        "SELECT id, username FROM users WHERE username = '" + username +
        "' AND password = '" + password + "'";

    auto db = drogon::app().getDbClient();
    db->execSqlAsync(
        vuln_sql,
        [callback](const drogon::orm::Result& result) {
            if (result.size() > 0) {
                Json::Value resp_body;
                resp_body["success"]  = true;
                resp_body["message"]  = "Login successful";
                resp_body["user_id"]  = result[0]["id"].as<int>();
                resp_body["username"] = result[0]["username"].as<std::string>();

                auto resp = drogon::HttpResponse::newHttpJsonResponse(resp_body);
                resp->setStatusCode(drogon::k200OK);
                callback(resp);
            } else {
                Json::Value resp_body;
                resp_body["success"] = false;
                resp_body["message"] = "Invalid credentials";

                auto resp = drogon::HttpResponse::newHttpJsonResponse(resp_body);
                resp->setStatusCode(drogon::k401Unauthorized);
                callback(resp);
            }
        },
        [callback](const drogon::orm::DrogonDbException& e) {
            Json::Value resp_body;
            resp_body["error"] = std::string(e.base().what());

            auto resp = drogon::HttpResponse::newHttpJsonResponse(resp_body);
            resp->setStatusCode(drogon::k500InternalServerError);
            callback(resp);
        });
}
