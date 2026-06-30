#include "AdminOnlyFilter.h"
#include <json/json.h>

void AdminOnlyFilter::doFilter(const drogon::HttpRequestPtr& req,
                               drogon::FilterCallback&& fcb,
                               drogon::FilterChainCallback&& fccb) {
    const std::string role = req->getAttributes()->get<std::string>("user_role");

    if (role != "admin") {
        Json::Value body;
        body["error"] = "Admin privileges required";
        auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
        resp->setStatusCode(drogon::k403Forbidden);
        fcb(resp);
        return;
    }

    fccb();
}
