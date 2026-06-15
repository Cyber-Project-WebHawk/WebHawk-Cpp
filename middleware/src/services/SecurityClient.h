#pragma once
#include <drogon/drogon.h>
#include <string>
#include <map>
#include <functional>

struct ScanRequest {
    std::string ip;
    std::string method;
    std::string path;
    std::map<std::string, std::string> queryParams;
    std::map<std::string, std::string> headers;
    std::string body;
};

struct ScanResult {
    bool safe;
    std::string attackType; // "SQLi", "XSS", "RateLimit", or ""
    std::string detail;
};

// Calls Student 2's security engine via HTTP
class SecurityClient {
public:
    explicit SecurityClient(const std::string& engineUrl);

    void scan(
        const ScanRequest& request,
        std::function<void(ScanResult)>&& callback,
        std::function<void(const std::string&)>&& errorCallback
    );

private:
    std::string engineUrl_;
};
