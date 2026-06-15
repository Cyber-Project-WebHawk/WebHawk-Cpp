#pragma once
#include <string>

class ApiKeyGenerator {
public:
    // Generates a unique 64-character hex API key using /dev/urandom
    static std::string generate();

private:
    ApiKeyGenerator() = delete; // pure static utility — never instantiate
};
