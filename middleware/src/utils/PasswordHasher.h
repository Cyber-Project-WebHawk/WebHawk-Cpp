#pragma once
#include <string>

// Argon2id password hashing backed by libsodium.
// - hash() returns a self-describing string (algorithm + params + salt + digest),
//   so no separate salt column is needed.
// - verify() is constant-time and reads the parameters embedded in the stored hash.
class PasswordHasher {
public:
    // Hashes a plaintext password. Throws std::runtime_error on failure.
    static std::string hash(const std::string& password);

    // Returns true if the password matches the stored Argon2id hash.
    static bool verify(const std::string& password, const std::string& storedHash);

private:
    // Initializes libsodium exactly once. Throws std::runtime_error on failure.
    static void ensureInit();

    PasswordHasher() = delete; // pure static utility — never instantiate
};
