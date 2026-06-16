#include <drogon/drogon.h>
#include "src/routes/ProxyRoute.h"
#include "src/routes/RegistrationRoute.h"
#include <iostream>

int main() {
    std::cout << "Step 1: main() started" << std::endl;
    std::flush(std::cout);

    const std::string dbHost     = getenv("DB_HOST")     ? getenv("DB_HOST")     : "localhost";
    const std::string dbName     = getenv("DB_NAME")     ? getenv("DB_NAME")     : "webhawk";
    const std::string dbUser     = getenv("DB_USER")     ? getenv("DB_USER")     : "webhawk";
    const std::string dbPassword = getenv("DB_PASSWORD") ? getenv("DB_PASSWORD") : "";

    std::cout << "Step 2: env vars loaded" << std::endl;
    std::flush(std::cout);

    drogon::orm::PostgresConfig pgConfig;
    pgConfig.host             = dbHost;
    pgConfig.port             = 5432;
    pgConfig.databaseName     = dbName;
    pgConfig.username         = dbUser;
    pgConfig.password         = dbPassword;
    pgConfig.connectionNumber = 1;
    pgConfig.name             = "default";
    pgConfig.isFast           = false;
    pgConfig.characterSet     = "";
    pgConfig.timeout          = 30.0;
    pgConfig.autoBatch        = false;

    std::cout << "Step 3: pgConfig built" << std::endl;
    std::flush(std::cout);

    drogon::app().addDbClient(pgConfig);

    std::cout << "Step 4: DB client added" << std::endl;
    std::flush(std::cout);

    drogon::app()
        .setLogPath("./")
        .setLogLevel(trantor::Logger::kInfo)
        .addListener("0.0.0.0", 8080)
        .setThreadNum(4)
        .run();

    return 0;
}