#pragma once
#include <drogon/drogon.h>
#include <memory>
#include "../services/RegistrationService.h"
#include "../repositories/BackendRepository.h"

class RegistrationRoute : public drogon::HttpController<RegistrationRoute> {
public:
    // All backend administration requires a valid admin access token.
    METHOD_LIST_BEGIN
        ADD_METHOD_TO(RegistrationRoute::registerBackend,   "/api/backends/register", drogon::Post,   "JwtAuthFilter", "AdminOnlyFilter");
        ADD_METHOD_TO(RegistrationRoute::listBackends,      "/api/backends",          drogon::Get,    "JwtAuthFilter", "AdminOnlyFilter");
        ADD_METHOD_TO(RegistrationRoute::deactivateBackend, "/api/backends/{id}",     drogon::Delete, "JwtAuthFilter", "AdminOnlyFilter");
    METHOD_LIST_END

    void registerBackend(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback
    );
    void listBackends(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback
    );
    void deactivateBackend(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback,
        int id
    );

private:
    // Lazy — created on first request, not at startup
    std::shared_ptr<RegistrationService> getService() {
        if (!service_) {
            auto db   = drogon::app().getDbClient();
            auto repo = std::make_shared<BackendRepository>(db);
            service_  = std::make_shared<RegistrationService>(repo);
        }
        return service_;
    }

    std::shared_ptr<RegistrationService> service_;
};