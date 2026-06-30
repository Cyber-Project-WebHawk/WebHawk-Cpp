#include "RateLimiter.h"
#include <drogon/drogon.h>
#include <memory>

void RateLimiter::checkBlocked(const std::string& ip,
                                std::function<void(bool)>&& callback) {
    const std::string key = "rate:" + ip;

    auto redis = drogon::app().getRedisClient();
    if (!redis) {
        // Redis unavailable — fail open (do not block traffic)
        callback(false);
        return;
    }

    // Wrap in shared_ptr so both the success and error lambdas can capture it.
    auto cb = std::make_shared<std::function<void(bool)>>(std::move(callback));

    redis->execCommandAsync(
        [key, cb](const drogon::nosql::RedisResult& result) {
            int count = static_cast<int>(result.asInteger());

            // On first request in a new window, set the 60-second TTL.
            if (count == 1) {
                if (auto red = drogon::app().getRedisClient()) {
                    red->execCommandAsync(
                        [](const drogon::nosql::RedisResult&) {},
                        [](const std::exception&) {},
                        "EXPIRE %s 60", key.c_str()
                    );
                }
            }

            (*cb)(count > MAX_REQUESTS_PER_MINUTE);
        },
        [cb](const std::exception& /*e*/) {
            // Redis error — fail open
            (*cb)(false);
        },
        "INCR %s", key.c_str()
    );
}
