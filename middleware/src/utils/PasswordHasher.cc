#include "PasswordHasher.h"
#include <sodium.h>
#include <mutex>
#include <stdexcept>

void PasswordHasher::ensureInit() {
    static std::once_flag initFlag;
    static bool initOk = false;
    std::call_once(initFlag, []() {
        // sodium_init() returns 0 on success, 1 if already initialized, -1 on failure.
        initOk = (sodium_init() >= 0);
    });
    if (!initOk) {
        throw std::runtime_error("PasswordHasher: libsodium initialization failed");
    }
}

std::string PasswordHasher::hash(const std::string& password) {
    ensureInit();

    char hashed[crypto_pwhash_STRBYTES];

    // INTERACTIVE limits are a sane CPU/memory trade-off for an auth endpoint.
    if (crypto_pwhash_str(
            hashed,
            password.c_str(),
            password.size(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        // The only documented failure is out-of-memory.
        throw std::runtime_error("PasswordHasher: hashing failed (out of memory)");
    }

    return std::string(hashed);
}

bool PasswordHasher::verify(const std::string& password, const std::string& storedHash) {
    ensureInit();

    return crypto_pwhash_str_verify(
               storedHash.c_str(),
               password.c_str(),
               password.size()) == 0;
}
