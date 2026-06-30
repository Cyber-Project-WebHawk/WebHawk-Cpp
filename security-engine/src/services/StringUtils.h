#pragma once

#include <string>
#include <algorithm>
#include <unordered_set>

inline std::string toLower(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

// Standard transport/negotiation headers that legitimate clients always send and
// that never carry user-controlled injection payloads. Scanning them produces
// false positives (e.g. `Accept: */*` matches the SQL block-comment pattern `*/`),
// so they are skipped. Headers attackers actually abuse (user-agent, referer,
// cookie, custom X-* headers, etc.) are still scanned. Names are lowercase
// because Drogon normalizes header field names to lowercase.
inline bool isScannableHeader(const std::string& name) {
    static const std::unordered_set<std::string> kSkip = {
        "accept", "accept-encoding", "accept-language", "accept-charset",
        "connection", "host", "content-length", "content-type",
        "cache-control", "upgrade-insecure-requests"
    };
    return kSkip.find(toLower(name)) == kSkip.end();
}
