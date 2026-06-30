#pragma once
#include <drogon/HttpFilter.h>

// Rejects requests without a valid "Authorization: Bearer <access-token>" header.
// On success, injects user_id / user_email / user_role into the request attributes
// for downstream handlers and filters.
class JwtAuthFilter : public drogon::HttpFilter<JwtAuthFilter> {
public:
    void doFilter(const drogon::HttpRequestPtr& req,
                  drogon::FilterCallback&& fcb,
                  drogon::FilterChainCallback&& fccb) override;
};
