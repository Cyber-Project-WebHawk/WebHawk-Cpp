#include <drogon/drogon.h>
#include "src/routes/VulnLoginRoute.h"
#include "src/routes/VulnSearchRoute.h"
#include "src/routes/VulnAdminRoute.h"

// INTENTIONALLY VULNERABLE BACKEND — FOR TESTING WEBHAWK ONLY

int main() {
    const std::string dbHost     = getenv("DB_HOST")     ? getenv("DB_HOST")     : "localhost";
    const std::string dbName     = getenv("DB_NAME")     ? getenv("DB_NAME")     : "webhawk";
    const std::string dbUser     = getenv("DB_USER")     ? getenv("DB_USER")     : "webhawk";
    const std::string dbPassword = getenv("DB_PASSWORD") ? getenv("DB_PASSWORD") : "";

    drogon::orm::PostgresConfig pgConfig;
    pgConfig.host             = dbHost;
    pgConfig.port             = 5432;
    pgConfig.databaseName     = dbName;
    pgConfig.username         = dbUser;
    pgConfig.password         = dbPassword;
    pgConfig.connectionNumber = 1;

    // No registerController — Drogon auto-discovers all HttpController subclasses
    drogon::app()
        .addDbClient(pgConfig)
        .setLogPath("./")
        .setLogLevel(trantor::Logger::kInfo)
        .addListener("0.0.0.0", 9090)
        .setThreadNum(2)
        .run();

    return 0;
}