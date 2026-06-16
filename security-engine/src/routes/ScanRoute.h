#pragma once

#include <drogon/drogon.h>

class ScanRoute : public drogon::HttpController<ScanRoute> {
public:
    ScanRoute() {}

    METHOD_LIST_BEGIN
        ADD_METHOD_TO(ScanRoute::scan, "/api/security/scan", drogon::Post);
    METHOD_LIST_END

    void scan(const drogon::HttpRequestPtr& req,
              std::function<void(const drogon::HttpResponsePtr&)>&& callback);
};
