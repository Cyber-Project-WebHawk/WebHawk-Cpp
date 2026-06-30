#pragma once

#include <string>
#include <map>

struct DetectionResult {
    bool safe;
    std::string detail;
};

class SqlInjectionDetector {
public:
    static DetectionResult scan(const std::string& path,
                                const std::map<std::string, std::string>& queryParams,
                                const std::string& body,
                                const std::map<std::string, std::string>& headers = {});

private:
    static bool containsSqli(const std::string& input, std::string& matchedPattern);
};
