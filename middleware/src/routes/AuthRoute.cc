#include "AuthRoute.h"
#include <json/json.h>

namespace {

drogon::HttpResponsePtr jsonError(const AuthError& err) {
    Json::Value body;
    body["error"] = err.message;
    auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
    resp->setStatusCode(static_cast<drogon::HttpStatusCode>(err.statusCode));
    return resp;
}

drogon::HttpResponsePtr jsonError(int status, const std::string& message) {
    return jsonError(AuthError{status, message});
}

std::string clientIp(const drogon::HttpRequestPtr& req) {
    return req->getPeerAddr().toIp();
}

std::string userAgent(const drogon::HttpRequestPtr& req) {
    return req->getHeader("user-agent");
}

} // namespace

// ── POST /api/auth/register ──────────────────────────────────────────────────

void AuthRoute::registerUser(
    const drogon::HttpRequestPtr& req,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback)
{
    auto json = req->getJsonObject();
    if (!json || !(*json)["email"].isString() || !(*json)["password"].isString()) {
        callback(jsonError(400, "Request body must contain 'email' and 'password'"));
        return;
    }

    getService()->registerUser(
        (*json)["email"].asString(),
        (*json)["password"].asString(),
        [callback](User user) {
            Json::Value body;
            body["id"]    = user.id;
            body["email"] = user.email;
            body["role"]  = user.role;
            auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
            resp->setStatusCode(drogon::k201Created);
            callback(resp);
        },
        [callback](AuthError err) { callback(jsonError(err)); }
    );
}

// ── POST /api/auth/login ─────────────────────────────────────────────────────

void AuthRoute::login(
    const drogon::HttpRequestPtr& req,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback)
{
    auto json = req->getJsonObject();
    if (!json || !(*json)["email"].isString() || !(*json)["password"].isString()) {
        callback(jsonError(400, "Request body must contain 'email' and 'password'"));
        return;
    }

    getService()->login(
        (*json)["email"].asString(),
        (*json)["password"].asString(),
        clientIp(req),
        userAgent(req),
        [callback](AuthTokens tokens) {
            Json::Value body;
            body["accessToken"]  = tokens.accessToken;
            body["refreshToken"] = tokens.refreshToken;
            body["tokenType"]    = "Bearer";
            Json::Value user;
            user["id"]    = tokens.userId;
            user["email"] = tokens.email;
            user["role"]  = tokens.role;
            body["user"]  = user;
            auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
            resp->setStatusCode(drogon::k200OK);
            callback(resp);
        },
        [callback](AuthError err) { callback(jsonError(err)); }
    );
}

// ── POST /api/auth/refresh ───────────────────────────────────────────────────

void AuthRoute::refresh(
    const drogon::HttpRequestPtr& req,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback)
{
    auto json = req->getJsonObject();
    if (!json || !(*json)["refreshToken"].isString()) {
        callback(jsonError(400, "Request body must contain 'refreshToken'"));
        return;
    }

    getService()->refresh(
        (*json)["refreshToken"].asString(),
        clientIp(req),
        userAgent(req),
        [callback](AuthTokens tokens) {
            Json::Value body;
            body["accessToken"]  = tokens.accessToken;
            body["refreshToken"] = tokens.refreshToken;
            body["tokenType"]    = "Bearer";
            auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
            resp->setStatusCode(drogon::k200OK);
            callback(resp);
        },
        [callback](AuthError err) { callback(jsonError(err)); }
    );
}

// ── POST /api/auth/logout (protected) ────────────────────────────────────────

void AuthRoute::logout(
    const drogon::HttpRequestPtr& req,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback)
{
    auto json = req->getJsonObject();
    if (!json || !(*json)["refreshToken"].isString()) {
        callback(jsonError(400, "Request body must contain 'refreshToken'"));
        return;
    }

    getService()->logout(
        (*json)["refreshToken"].asString(),
        [callback]() {
            Json::Value body;
            body["message"] = "Logged out";
            auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
            resp->setStatusCode(drogon::k200OK);
            callback(resp);
        },
        [callback](AuthError err) { callback(jsonError(err)); }
    );
}

// ── GET /api/auth/me (protected) ─────────────────────────────────────────────

void AuthRoute::me(
    const drogon::HttpRequestPtr& req,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback)
{
    // user_id is injected by JwtAuthFilter after verifying the access token.
    const int userId = req->getAttributes()->get<int>("user_id");
    if (userId <= 0) {
        callback(jsonError(401, "Unauthorized"));
        return;
    }

    getService()->getCurrentUser(
        userId,
        [callback](User user) {
            Json::Value body;
            body["id"]    = user.id;
            body["email"] = user.email;
            body["role"]  = user.role;
            auto resp = drogon::HttpResponse::newHttpJsonResponse(body);
            resp->setStatusCode(drogon::k200OK);
            callback(resp);
        },
        [callback](AuthError err) { callback(jsonError(err)); }
    );
}
