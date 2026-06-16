#pragma once

#include <string>

class SecurityLogRepository {
public:
    static void log(const std::string& ip,
                    const std::string& method,
                    const std::string& endpoint,
                    const std::string& attackType,
                    const std::string& rawPayload);
};
