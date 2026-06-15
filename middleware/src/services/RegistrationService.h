#pragma once
#include <string>
#include <functional>
#include <memory>
#include <vector>
#include "../repositories/BackendRepository.h"

struct RegistrationRequest {
    std::string serviceName;
    std::string targetUrl;
};

struct RegistrationResult {
    Backend backend;
    std::string apiKey;
};

class RegistrationService {
public:
    explicit RegistrationService(std::shared_ptr<BackendRepository> repo);

    void registerBackend(
        const RegistrationRequest& request,
        std::function<void(RegistrationResult)>&& callback,
        std::function<void(const std::string&)>&& errorCallback
    );

    void listBackends(
        std::function<void(std::vector<Backend>)>&& callback,
        std::function<void(const std::string&)>&& errorCallback
    );

    void deactivateBackend(
        int id,
        std::function<void()>&& callback,
        std::function<void(const std::string&)>&& errorCallback
    );

private:
    std::shared_ptr<BackendRepository> repo_;
};
