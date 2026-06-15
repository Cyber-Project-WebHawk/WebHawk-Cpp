#pragma once
#include <drogon/drogon.h>

// INTENTIONALLY VULNERABLE — FOR TESTING WEBHAWK ONLY
// DO NOT USE IN PRODUCTION
// Vulnerability: no authentication check on admin endpoint
class VulnAdminRoute : public drogon::HttpController<VulnAdminRoute> {
public:
    METHOD_LIST_BEGIN
        ADD_METHOD_TO(VulnAdminRoute::getAdminData, "/vuln/admin", drogon::Get);
        ADD_METHOD_TO(VulnAdminRoute::healthCheck,  "/vuln/ping",  drogon::Get);
    METHOD_LIST_END

    // Vulnerable: returns sensitive data with zero auth check
    void getAdminData(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback
    );

    // Safe: health check endpoint
    void healthCheck(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback
    );
};
