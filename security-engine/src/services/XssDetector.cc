#include "XssDetector.h"
#include "StringUtils.h"
#include <vector>

static const std::vector<std::string> XSS_PATTERNS = {
    "<script",
    "</script>",
    "javascript:",
    "vbscript:",
    "onload=",
    "onerror=",
    "onclick=",
    "onmouseover=",
    "onfocus=",
    "onblur=",
    "onkeydown=",
    "onkeyup=",
    "onsubmit=",
    "<iframe",
    "<img",
    "<svg",
    "<body",
    "<input",
    "<link",
    "<meta",
    "alert(",
    "document.cookie",
    "document.write",
    "window.location",
    "eval(",
    "expression(",
    "url(javascript",
    "src=javascript",
    "href=javascript",
    "&#",
    "%3cscript",
    "%3c"
};

bool XssDetector::containsXss(const std::string& input, std::string& matchedPattern) {
    std::string lower = toLower(input);
    for (const auto& pattern : XSS_PATTERNS) {
        if (lower.find(pattern) != std::string::npos) {
            matchedPattern = pattern;
            return true;
        }
    }
    return false;
}

DetectionResult XssDetector::scan(const std::string& path,
                                   const std::map<std::string, std::string>& queryParams,
                                   const std::string& body) {
    std::string matched;

    // Check the URL path
    if (containsXss(path, matched)) {
        return { false, "XSS pattern found in path: " + matched };
    }

    // Check each query parameter value
    for (const auto& [key, value] : queryParams) {
        if (containsXss(value, matched)) {
            return { false, "XSS pattern found in query param '" + key + "': " + matched };
        }
    }

    // Check the request body
    if (containsXss(body, matched)) {
        return { false, "XSS pattern found in body: " + matched };
    }

    return { true, "" };
}
