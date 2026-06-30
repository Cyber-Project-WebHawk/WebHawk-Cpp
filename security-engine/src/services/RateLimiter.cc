#include "RateLimiter.h"
#include <drogon/drogon.h>
#include <atomic>
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

    // The callback must run exactly once — whichever happens first wins:
    // the Redis reply, a Redis error, or the safety timeout. This guards against
    // a stalled/unconnected Redis leaving the scan (and the proxy) hanging.
    auto cb   = std::make_shared<std::function<void(bool)>>(std::move(callback));
    auto done = std::make_shared<std::atomic_bool>(false);

    auto fire = [cb, done](bool blocked) {
        bool expected = false;
        if (done->compare_exchange_strong(expected, true)) {
            (*cb)(blocked);
        }
    };

    // Safety net: never let Redis stall a scan. Fail open after 2 seconds.
    drogon::app().getLoop()->runAfter(2.0, [fire]() { fire(false); });

    redis->execCommandAsync(
        [key, fire](const drogon::nosql::RedisResult& result) {
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

            fire(count > MAX_REQUESTS_PER_MINUTE);
        },
        [fire](const std::exception& /*e*/) {
            // Redis error — fail open
            fire(false);
        },
        "INCR %s", key.c_str()
    );
}
