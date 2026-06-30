#pragma once
#include <drogon/HttpFilter.h>

// Requires the authenticated user to have the "admin" role.
// MUST be listed AFTER JwtAuthFilter, which populates the user_role attribute.
class AdminOnlyFilter : public drogon::HttpFilter<AdminOnlyFilter> {
public:
    void doFilter(const drogon::HttpRequestPtr& req,
                  drogon::FilterCallback&& fcb,
                  drogon::FilterChainCallback&& fccb) override;
};
