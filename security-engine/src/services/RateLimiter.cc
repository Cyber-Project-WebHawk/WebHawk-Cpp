#include "RateLimiter.h"
#include <drogon/drogon.h>

bool RateLimiter::isBlocked(const std::string& ip) {
    const std::string key = "rate:" + ip;

    auto redis = drogon::app().getRedisClient();
    if (!redis) {
        return false;
    }

    bool blocked = false;

    // Use a promise/future pair to wait for the async Redis result
    // without blocking the event loop thread
    std::promise<int> promise;
    auto future = promise.get_future();

    redis->execCommandAsync(
        [&promise](const drogon::nosql::RedisResult& result) {
            promise.set_value(static_cast<int>(result.asInteger()));
        },
        [&promise](const std::exception& e) {
            promise.set_value(0);
        },
        "INCR %s", key.c_str()
    );

    int count = future.get();

    // Set expiry on first request in the window
    if (count == 1) {
        redis->execCommandAsync(
            [](const drogon::nosql::RedisResult&) {},
            [](const std::exception&) {},
            "EXPIRE %s 60", key.c_str()
        );
    }

    return count > MAX_REQUESTS_PER_MINUTE;
}
