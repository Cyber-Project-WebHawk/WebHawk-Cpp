#pragma once
#include <drogon/drogon.h>

// INTENTIONALLY VULNERABLE — FOR TESTING WEBHAWK ONLY
// DO NOT USE IN PRODUCTION
// Vulnerability: raw SQL string concatenation → SQL Injection
class VulnLoginRoute : public drogon::HttpController<VulnLoginRoute> {
public:
    METHOD_LIST_BEGIN
        ADD_METHOD_TO(VulnLoginRoute::login, "/vuln/login", drogon::Post);
    METHOD_LIST_END

    // Vulnerable: concatenates username directly into SQL query
    void login(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback
    );
};
