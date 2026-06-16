// INTENTIONALLY VULNERABLE — FOR TESTING WEBHAWK ONLY
// DO NOT USE IN PRODUCTION
// Vulnerability: /vuln/admin returns sensitive data with zero authentication check

#include "VulnAdminRoute.h"
#include <json/json.h>

void VulnAdminRoute::getAdminData(
    const drogon::HttpRequestPtr& req,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback)
{
    // INTENTIONAL VULNERABILITY: no token, session, or role check whatsoever
    Json::Value users(Json::arrayValue);

    Json::Value user1;
    user1["id"]           = 1;
    user1["username"]     = "admin";
    user1["password_hash"] = "$2b$12$KIXnotAR3ealHashButFakeForTesting";
    user1["role"]         = "superadmin";
    user1["email"]        = "admin@internal.webhawk.local";
    users.append(user1);

    Json::Value user2;
    user2["id"]           = 2;
    user2["username"]     = "john.doe";
    user2["password_hash"] = "$2b$12$AnotherFakeHashForTestingOnly1234";
    user2["role"]         = "user";
    user2["email"]        = "john.doe@internal.webhawk.local";
    users.append(user2);

    Json::Value secrets;
    secrets["db_connection_string"] = "postgresql://webhawk:s3cr3t@db:5432/webhawk";
    secrets["jwt_secret"]           = "super-secret-jwt-key-do-not-expose";
    secrets["internal_api_key"]     = "ik_live_abc123def456ghi789jkl000";

    Json::Value body;
    body["users"]       = users;
    body["secrets"]     = secrets;
    body["server_info"] = "VulnBackend v1.0 — running as root";

    auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
    resp->setStatusCode(drogon::k200OK);
    callback(resp);
}

void VulnAdminRoute::healthCheck(
    const drogon::HttpRequestPtr& req,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback)
{
    Json::Value body;
    body["status"]  = "ok";
    body["service"] = "vulnerable-backend";

    auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
    resp->setStatusCode(drogon::k200OK);
    callback(resp);
}
