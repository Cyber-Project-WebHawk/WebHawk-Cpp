#pragma once

#include <string>
#include <map>
#include "SqlInjectionDetector.h"

class XssDetector {
public:
    static DetectionResult scan(const std::string& path,
                                const std::map<std::string, std::string>& queryParams,
                                const std::string& body);

private:
    static bool containsXss(const std::string& input, std::string& matchedPattern);
};
