#include "SecurityLogRepository.h"
#include <drogon/drogon.h>

void SecurityLogRepository::log(int backendId,
                                 const std::string& ip,
                                 const std::string& method,
                                 const std::string& endpoint,
                                 const std::string& attackType,
                                 const std::string& rawPayload) {

    auto db = drogon::app().getDbClient();
    if (!db) return;

    // backend_id is stored as NULL when it is 0 (unknown).
    if (backendId > 0) {
        db->execSqlAsync(
            "INSERT INTO security_logs "
            "(backend_id, ip_address, method, endpoint, attack_type, was_blocked, raw_payload, detected_at) "
            "VALUES ($1, $2, $3, $4, $5, TRUE, $6, NOW())",
            [](const drogon::orm::Result&) {},
            [](const drogon::orm::DrogonDbException& e) {
                LOG_ERROR << "Failed to log attack: " << e.base().what();
            },
            backendId, ip, method, endpoint, attackType, rawPayload
        );
    } else {
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
}
