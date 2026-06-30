#pragma once
#include <drogon/drogon.h>
#include <string>
#include <optional>
#include <functional>

struct User {
    int         id = 0;
    std::string email;
    std::string passwordHash;
    std::string role = "user";
    int         failedLoginAttempts = 0;
    bool        isLocked = false; // computed: locked_until is in the future
};

// Database access for the `users` table. Queries only — no business logic.
class UserRepository {
public:
    explicit UserRepository(const drogon::orm::DbClientPtr& dbClient);

    void create(
        const std::string& email,
        const std::string& passwordHash,
        const std::string& role,
        std::function<void(User)>&& callback,
        std::function<void(const std::string&)>&& errorCallback
    );

    // Total number of registered users (used to bootstrap the first admin).
    void countUsers(
        std::function<void(int)>&& callback,
        std::function<void(const std::string&)>&& errorCallback
    );

    void findByEmail(
        const std::string& email,
        std::function<void(std::optional<User>)>&& callback,
        std::function<void(const std::string&)>&& errorCallback
    );

    void findById(
        int id,
        std::function<void(std::optional<User>)>&& callback,
        std::function<void(const std::string&)>&& errorCallback
    );

    // Increments the failed-login counter and returns the new value.
    void recordFailedAttempt(
        int id,
        std::function<void(int)>&& callback,
        std::function<void(const std::string&)>&& errorCallback
    );

    // Locks the account for `lockSeconds` from now.
    void lockAccount(
        int id,
        int lockSeconds,
        std::function<void()>&& callback,
        std::function<void(const std::string&)>&& errorCallback
    );

    // Clears the failed-login counter and any lock (called on successful login).
    void resetFailedAttempts(
        int id,
        std::function<void()>&& callback,
        std::function<void(const std::string&)>&& errorCallback
    );

private:
    drogon::orm::DbClientPtr dbClient_;
};
