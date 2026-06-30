#include "SecurityClient.h"
#include <json/json.h>

SecurityClient::SecurityClient(const std::string& engineUrl)
    : engineUrl_(engineUrl) {}

void SecurityClient::scan(
    const ScanRequest& request,
    std::function<void(ScanResult)>&& callback,
    std::function<void(const std::string&)>&& errorCallback)
{
    // ── build request body ────────────────────────────────────────────────────
    Json::Value body;
    body["backend_id"] = request.backendId;
    body["ip"]         = request.ip;
    body["method"]     = request.method;
    body["path"]       = request.path;
    body["body"]       = request.body;

    Json::Value query_params(Json::objectValue);
    for (const auto& [k, v] : request.queryParams) {
        query_params[k] = v;
    }
    body["query_params"] = query_params;

    Json::Value headers(Json::objectValue);
    for (const auto& [k, v] : request.headers) {
        headers[k] = v;
    }
    body["headers"] = headers;

    // ── build Drogon HTTP request ─────────────────────────────────────────────
    auto scanReq = drogon::HttpRequest::newHttpJsonRequest(body);
    scanReq->setMethod(drogon::Post);
    scanReq->setPath("/api/security/scan");

    auto client = drogon::HttpClient::newHttpClient(engineUrl_);
    client->sendRequest(
        scanReq,
        [client,
         callback      = std::move(callback),
         errorCallback = std::move(errorCallback)]
        (drogon::ReqResult result, const drogon::HttpResponsePtr& resp) {
            if (result != drogon::ReqResult::Ok || !resp) {
                errorCallback("SecurityClient: HTTP request to security engine failed");
                return;
            }

            if (resp->getStatusCode() != drogon::k200OK) {
                errorCallback("SecurityClient: security engine returned status " +
                              std::to_string(static_cast<int>(resp->getStatusCode())));
                return;
            }

            auto json = resp->getJsonObject();
            if (!json) {
                errorCallback("SecurityClient: could not parse security engine response as JSON");
                return;
            }

            // ── parse ScanResult ──────────────────────────────────────────────
            ScanResult scanResult;
            scanResult.safe       = (*json)["safe"].asBool();
            scanResult.attackType = (*json).get("attack_type", "").asString();
            scanResult.detail     = (*json).get("detail", "").asString();

            callback(std::move(scanResult));
        },
        10.0 /* timeout seconds */);
}
