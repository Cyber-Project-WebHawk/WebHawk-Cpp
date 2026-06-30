#pragma once
#include <drogon/drogon.h>
#include <memory>
#include <mutex>
#include "../services/AuthService.h"
#include "../repositories/UserRepository.h"
#include "../repositories/SessionRepository.h"

// HTTP layer for authentication. Parses requests, delegates to AuthService,
// and renders responses. No business logic, no SQL.
class AuthRoute : public drogon::HttpController<AuthRoute> {
public:
    METHOD_LIST_BEGIN
        ADD_METHOD_TO(AuthRoute::registerUser, "/api/auth/register", drogon::Post);
        ADD_METHOD_TO(AuthRoute::login,        "/api/auth/login",    drogon::Post);
        ADD_METHOD_TO(AuthRoute::refresh,      "/api/auth/refresh",  drogon::Post);
        // Protected: require a valid access token (JwtAuthFilter).
        ADD_METHOD_TO(AuthRoute::logout,       "/api/auth/logout",   drogon::Post, "JwtAuthFilter");
        ADD_METHOD_TO(AuthRoute::me,           "/api/auth/me",       drogon::Get,  "JwtAuthFilter");
    METHOD_LIST_END

    void registerUser(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback
    );
    void login(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback
    );
    void refresh(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback
    );
    void logout(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback
    );
    void me(
        const drogon::HttpRequestPtr& req,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback
    );

private:
    // Lazy — created on first request, not at startup (DB client not ready at ctor time).
    // Guarded by mutex_ to be safe under concurrent first requests.
    std::shared_ptr<AuthService> getService() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!service_) {
            auto db       = drogon::app().getDbClient();
            auto users    = std::make_shared<UserRepository>(db);
            auto sessions = std::make_shared<SessionRepository>(db);
            service_      = std::make_shared<AuthService>(users, sessions);
        }
        return service_;
    }

    std::shared_ptr<AuthService> service_;
    std::mutex mutex_;
};
