#include <drogon/drogon.h>

int main() {
    const std::string dbHost     = getenv("DB_HOST")     ? getenv("DB_HOST")     : "localhost";
    const std::string dbName     = getenv("DB_NAME")     ? getenv("DB_NAME")     : "webhawk";
    const std::string dbUser     = getenv("DB_USER")     ? getenv("DB_USER")     : "webhawk";
    const std::string dbPassword = getenv("DB_PASSWORD") ? getenv("DB_PASSWORD") : "";

    // New Drogon API — use PostgresConfig struct, not connection string
    drogon::orm::PostgresConfig pgConfig;
    pgConfig.host     = dbHost;
    pgConfig.port     = 5432;
    pgConfig.databaseName = dbName;
    pgConfig.username = dbUser;
    pgConfig.password = dbPassword;
    pgConfig.connectionNumber = 1;

    drogon::app()
        .addDbClient(pgConfig)
        .setLogPath("./")
        .setLogLevel(trantor::Logger::kInfo)
        .addListener("0.0.0.0", 8080)
        .setThreadNum(4)
        .run();

    return 0;
}