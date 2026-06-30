#include <drogon/drogon.h>

int main() {
    const std::string dbHost    = getenv("DB_HOST")     ? getenv("DB_HOST")     : "localhost";
    const std::string dbName    = getenv("DB_NAME")     ? getenv("DB_NAME")     : "webhawk";
    const std::string dbUser    = getenv("DB_USER")     ? getenv("DB_USER")     : "webhawk";
    const std::string dbPass    = getenv("DB_PASSWORD") ? getenv("DB_PASSWORD") : "";
    const std::string redisHost = getenv("REDIS_HOST")  ? getenv("REDIS_HOST")  : "localhost";

    drogon::orm::PostgresConfig pgConfig;
    pgConfig.host             = dbHost;
    pgConfig.port             = 5432;
    pgConfig.databaseName     = dbName;
    pgConfig.username         = dbUser;
    pgConfig.password         = dbPass;
    pgConfig.connectionNumber = 4;
    pgConfig.name             = "default";
    pgConfig.isFast           = false;
    pgConfig.characterSet     = "";
    pgConfig.timeout          = 30.0;
    pgConfig.autoBatch        = false;

    drogon::nosql::RedisConfig redisConfig;
    redisConfig.host           = redisHost;
    redisConfig.port           = 6379;
    redisConfig.connectionNumber = 4;
    redisConfig.name           = "default";

    drogon::app()
        .addDbClient(pgConfig)
        .addRedisClient(redisConfig)
        .setLogPath("./")
        .setLogLevel(trantor::Logger::kInfo)
        .setThreadNum(4)
        .addListener("0.0.0.0", 8081)
        .run();

    return 0;
}