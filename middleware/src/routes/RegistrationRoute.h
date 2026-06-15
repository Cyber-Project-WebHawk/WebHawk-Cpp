#pragma once
#include <drogon/drogon.h>
#include <memory>
#include "../services/RegistrationService.h"
#include "../repositories/BackendRepository.h"

class RegistrationRoute : public drogon::HttpController<RegistrationRoute> {
public:
    // Default constructor — Drogon requires this
    RegistrationRoute() {
        auto dbClient = drogon::app().getDbClient();
        auto repo     = std::make_shared<BackendRepository>(dbClient);
        service_      = std::make_shared<RegistrationService>(repo);
    }

    METHOD_LIST_BEGIN
        ADD_METHOD_TO(RegistrationRoute::registerBackend,   "/api/backends/register", drogon::Post);
        ADD_METHOD_TO(RegistrationRoute::listBackends,      "/api/backends",          drogon::Get);
        ADD_METHOD_TO(RegistrationRoute::deactivateBackend, "/api/backends/{id}",     drogon::Delete);
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
    std::shared_ptr<RegistrationService> service_;
};