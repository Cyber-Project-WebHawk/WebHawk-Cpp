#include "SecurityLogRepository.h"
#include <drogon/drogon.h>

void SecurityLogRepository::log(const std::string& ip,
                                 const std::string& method,
                                 const std::string& endpoint,
                                 const std::string& attackType,
                                 const std::string& rawPayload) {

    auto db = drogon::app().getDbClient();
    if (!db) return;

    // Insert a row into security_logs table
    // $1, $2... are placeholders — Drogon fills them safely (no SQL injection possible here)
    db->execSqlAsync(
        "INSERT INTO security_logs "
        "(ip_address, method, endpoint, attack_type, was_blocked, raw_payload, detected_at) "
        "VALUES ($1, $2, $3, $4, TRUE, $5, NOW())",
        [](const drogon::orm::Result&) {},
        [](const drogon::orm::DrogonDbException& e) {
            LOG_ERROR << "Failed to log attack: " << e.base().what();
        },
        ip, method, endpoint, attackType, rawPayload
    );
}
