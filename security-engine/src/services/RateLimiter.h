#pragma once

#include <string>
#include <future>

class RateLimiter {
public:
    // Returns true if this IP has exceeded the request limit
    static bool isBlocked(const std::string& ip);

private:
    static constexpr int MAX_REQUESTS_PER_MINUTE = 100;
};
