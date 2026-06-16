// INTENTIONALLY VULNERABLE — FOR TESTING WEBHAWK ONLY
#include "VulnLoginRoute.h"
#include <json/json.h>

void VulnLoginRoute::login(
    const drogon::HttpRequestPtr& req,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback)
{
    std::string username;
    std::string password;

    auto body_json = req->getJsonObject();
    if (body_json && !body_json->isNull()) {
        if ((*body_json).isMember("username"))
            username = (*body_json)["username"].asString();
        if ((*body_json).isMember("password"))
            password = (*body_json)["password"].asString();
    }

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

    // INTENTIONAL VULNERABILITY: show the raw SQL that would be executed
    const std::string vuln_sql =
        "SELECT * FROM users WHERE username = '" + username +
        "' AND password = '" + password + "'";

    Json::Value resp_body;

    // Simulate SQLi bypass — if payload contains OR or --, "auth succeeds"
    if (username.find("'") != std::string::npos ||
        username.find("--") != std::string::npos ||
        username.find("OR") != std::string::npos ||
        username.find("or") != std::string::npos) {
        resp_body["success"]       = true;
        resp_body["message"]       = "Login successful (SQL INJECTION DETECTED)";
        resp_body["injected_sql"]  = vuln_sql;
        resp_body["warning"]       = "This request should have been blocked by WebHawk!";
        auto resp = drogon::HttpResponse::newHttpJsonResponse(resp_body);
        resp->setStatusCode(drogon::k200OK);
        callback(resp);
    } else {
        resp_body["success"]      = false;
        resp_body["message"]      = "Invalid credentials";
        resp_body["executed_sql"] = vuln_sql;
        auto resp = drogon::HttpResponse::newHttpJsonResponse(resp_body);
        resp->setStatusCode(drogon::k401Unauthorized);
        callback(resp);
    }
}