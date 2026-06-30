#include "SqlInjectionDetector.h"
#include "StringUtils.h"
#include <vector>

// Patterns that indicate a SQL injection attempt
static const std::vector<std::string> SQLI_PATTERNS = {
    "'",
    "--",
    ";--",
    "/*",
    "*/",
    "xp_",
    "1=1",
    "or 1=1",
    "' or '",
    "union select",
    "select ",
    "insert ",
    "update ",
    "delete ",
    "drop ",
    "create ",
    "alter ",
    "exec(",
    "execute(",
    "cast(",
    "convert(",
    "char(",
    "nchar(",
    "varchar(",
    "sleep(",
    "waitfor delay",
    "benchmark(",
    "information_schema",
    "sys.tables",
    "@@version"
};

bool SqlInjectionDetector::containsSqli(const std::string& input, std::string& matchedPattern) {
    std::string lower = toLower(input);
    for (const auto& pattern : SQLI_PATTERNS) {
        if (lower.find(pattern) != std::string::npos) {
            matchedPattern = pattern;
            return true;
        }
    }
    return false;
}

DetectionResult SqlInjectionDetector::scan(const std::string& path,
                                            const std::map<std::string, std::string>& queryParams,
                                            const std::string& body,
                                            const std::map<std::string, std::string>& headers) {
    std::string matched;

    if (containsSqli(path, matched))
        return { false, "SQLi pattern found in path: " + matched };

    for (const auto& [key, value] : queryParams) {
        if (containsSqli(value, matched))
            return { false, "SQLi pattern found in query param '" + key + "': " + matched };
    }

    if (containsSqli(body, matched))
        return { false, "SQLi pattern found in body: " + matched };

    for (const auto& [name, value] : headers) {
        if (!isScannableHeader(name)) continue;
        if (containsSqli(value, matched))
            return { false, "SQLi pattern found in header '" + name + "': " + matched };
    }

    return { true, "" };
}
