#include <drogon/drogon.h>
#include "src/routes/VulnLoginRoute.h"
#include "src/routes/VulnSearchRoute.h"
#include "src/routes/VulnAdminRoute.h"

// INTENTIONALLY VULNERABLE BACKEND — FOR TESTING WEBHAWK ONLY
// DO NOT EXPOSE THIS TO THE INTERNET

int main() {
    const std::string dbHost     = getenv("DB_HOST")     ? getenv("DB_HOST")     : "localhost";
    const std::string dbPort     = getenv("DB_PORT")     ? getenv("DB_PORT")     : "5432";
    const std::string dbName     = getenv("DB_NAME")     ? getenv("DB_NAME")     : "webhawk";
    const std::string dbUser     = getenv("DB_USER")     ? getenv("DB_USER")     : "webhawk";
    const std::string dbPassword = getenv("DB_PASSWORD") ? getenv("DB_PASSWORD") : "";

    drogon::app().addDbClient(
        drogon::orm::DbClient::newPgClient(
            "host=" + dbHost +
            " port=" + dbPort +
            " dbname=" + dbName +
            " user=" + dbUser +
            " password=" + dbPassword,
            1
        )
    );

    drogon::app().registerController(std::make_shared<VulnLoginRoute>());
    drogon::app().registerController(std::make_shared<VulnSearchRoute>());
    drogon::app().registerController(std::make_shared<VulnAdminRoute>());

    drogon::app()
        .setLogPath("./")
        .setLogLevel(trantor::Logger::kInfo)
        .addListener("0.0.0.0", 9090)
        .setThreadNum(2)
        .run();

    return 0;
}
