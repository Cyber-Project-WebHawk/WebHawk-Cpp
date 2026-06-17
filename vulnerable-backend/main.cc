#include <drogon/drogon.h>
#include "src/routes/VulnLoginRoute.h"
#include "src/routes/VulnSearchRoute.h"
#include "src/routes/VulnAdminRoute.h"

// INTENTIONALLY VULNERABLE BACKEND — FOR TESTING WEBHAWK ONLY

int main() {
    // No DB connection — vulnerable backend is self-contained
    drogon::app()
        .setLogPath("./")
        .setLogLevel(trantor::Logger::kInfo)
        .addListener("0.0.0.0", 9090)
        .setThreadNum(2)
        .run();

    return 0;
}