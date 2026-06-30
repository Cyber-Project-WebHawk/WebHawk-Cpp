#include <drogon/drogon.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <string>

// Drogon's Redis client (via trantor::InetAddress) does NOT resolve hostnames —
// passing a Docker service name like "redis" silently binds to 0.0.0.0 and never
// connects. Resolve to an IPv4 address first so the client can actually connect.
static std::string resolveHost(const std::string& host) {
    struct addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || res == nullptr) {
        return host; // fall back to the original value; let Drogon log the failure
    }

    char buf[INET_ADDRSTRLEN] = {0};
    auto* addr = reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
    inet_ntop(AF_INET, &addr->sin_addr, buf, sizeof(buf));
    freeaddrinfo(res);

    return buf[0] ? std::string(buf) : host;
}

int main() {
    const std::string dbHost    = getenv("DB_HOST")     ? getenv("DB_HOST")     : "localhost";
    const std::string dbName    = getenv("DB_NAME")     ? getenv("DB_NAME")     : "webhawk";
    const std::string dbUser    = getenv("DB_USER")     ? getenv("DB_USER")     : "webhawk";
    const std::string dbPass    = getenv("DB_PASSWORD") ? getenv("DB_PASSWORD") : "";
    const std::string redisHost = getenv("REDIS_HOST")  ? getenv("REDIS_HOST")  : "localhost";
    const std::string redisIp   = resolveHost(redisHost);

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

    drogon::app()
        .addDbClient(pgConfig)
        .createRedisClient(redisIp, 6379, "default", "", 4)
        .setLogPath("./")
        .setLogLevel(trantor::Logger::kInfo)
        .setThreadNum(4)
        .addListener("0.0.0.0", 8081)
        .run();

    return 0;
}