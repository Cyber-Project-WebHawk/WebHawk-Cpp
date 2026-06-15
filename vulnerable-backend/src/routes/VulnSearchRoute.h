#pragma once
#include <drogon/drogon.h>

// INTENTIONALLY VULNERABLE — FOR TESTING WEBHAWK ONLY
// DO NOT USE IN PRODUCTION
// Vulnerability: echoes query param directly into HTML → XSS
class VulnSearchRoute : public drogon::HttpController<VulnSearchRoute> {
public:
    METHOD_LIST_BEGIN
        ADD_METHOD_TO(VulnSearchRoute::search, "/vuln/search", drogon::Get);
    METHOD_LIST_END

    // Vulnerable: echoes ?q= param directly into HTML response without sanitization
    void search(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback
    );
};
