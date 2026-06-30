#pragma once

#include <string>
#include <functional>

class RateLimiter {
public:
    // Async: calls callback(true) if this IP is rate-limited, callback(false) if safe.
    // Never blocks the event loop.
    static void checkBlocked(const std::string& ip,
                              std::function<void(bool)>&& callback);

private:
    static constexpr int MAX_REQUESTS_PER_MINUTE = 100;
};
