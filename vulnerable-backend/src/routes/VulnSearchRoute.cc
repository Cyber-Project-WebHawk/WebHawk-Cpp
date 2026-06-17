// INTENTIONALLY VULNERABLE — FOR TESTING WEBHAWK ONLY
// DO NOT USE IN PRODUCTION
// Vulnerability: ?q= value is spliced raw into the HTML response body → XSS
// A payload like:  <script>alert(1)</script>  executes in the browser as-is.

#include "VulnSearchRoute.h"

void VulnSearchRoute::search(
    const drogon::HttpRequestPtr& req,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback)
{
    auto params = req->getParameters();

    // INTENTIONAL VULNERABILITY: no HTML-encoding, no sanitization whatsoever
    const std::string query = params.count("q") ? params.at("q") : "";

    const std::string html =
        "<!DOCTYPE html>"
        "<html><head><title>Search</title></head>"
        "<body>"
        "<h1>Search Results</h1>"
        "<form method=\"GET\" action=\"/vuln/search\">"
        "  <input type=\"text\" name=\"q\" value=\"" + query + "\">"
        "  <button type=\"submit\">Search</button>"
        "</form>"
        "<p>You searched for: " + query + "</p>"
        "</body></html>";

    auto resp = drogon::HttpResponse::newHttpResponse();
    resp->setStatusCode(drogon::k200OK);
    resp->setContentTypeCode(drogon::CT_TEXT_HTML);
    resp->setBody(html);
    callback(resp);
}
