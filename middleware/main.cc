#include <drogon/drogon.h>
#include <memory>
#include "src/repositories/BackendRepository.h"
#include "src/services/SecurityClient.h"
#include "src/services/RegistrationService.h"
#include "src/services/ProxyService.h"
#include "src/routes/RegistrationRoute.h"
#include "src/routes/ProxyRoute.h"

int main() {
    // Load environment variables
    const std::string dbHost     = getenv("DB_HOST")     ? getenv("DB_HOST")     : "localhost";
    const std::string dbPort     = getenv("DB_PORT")     ? getenv("DB_PORT")     : "5432";
    const std::string dbName     = getenv("DB_NAME")     ? getenv("DB_NAME")     : "webhawk";
    const std::string dbUser     = getenv("DB_USER")     ? getenv("DB_USER")     : "webhawk";
    const std::string dbPassword = getenv("DB_PASSWORD") ? getenv("DB_PASSWORD") : "";
    const std::string engineUrl  = getenv("SECURITY_ENGINE_URL") ? getenv("SECURITY_ENGINE_URL") : "http://localhost:8081";

    // Setup PostgreSQL connection
    drogon::app().addDbClient(
        drogon::orm::DbClient::newPgClient(
            "host=" + dbHost +
            " port=" + dbPort +
            " dbname=" + dbName +
            " user=" + dbUser +
            " password=" + dbPassword,
            1 // connection pool size
        )
    );

    // Wire up dependencies (Dependency Injection)
    auto dbClient           = drogon::app().getDbClient();
    auto backendRepo        = std::make_shared<BackendRepository>(dbClient);
    auto securityClient     = std::make_shared<SecurityClient>(engineUrl);
    auto registrationService = std::make_shared<RegistrationService>(backendRepo);
    auto proxyService       = std::make_shared<ProxyService>(backendRepo, securityClient);

    // Register routes
    drogon::app().registerController(std::make_shared<RegistrationRoute>(registrationService));
    drogon::app().registerController(std::make_shared<ProxyRoute>(proxyService));

    // Start server on port 8080
    drogon::app()
        .setLogPath("./")
        .setLogLevel(trantor::Logger::kInfo)
        .addListener("0.0.0.0", 8080)
        .setThreadNum(4)
        .run();

    return 0;
}
