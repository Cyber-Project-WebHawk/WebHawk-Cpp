#include "RegistrationService.h"
#include "../utils/ApiKeyGenerator.h"

RegistrationService::RegistrationService(std::shared_ptr<BackendRepository> repo)
    : repo_(std::move(repo)) {}

void RegistrationService::registerBackend(
    const RegistrationRequest& request,
    std::function<void(RegistrationResult)>&& callback,
    std::function<void(const std::string&)>&& errorCallback)
{
    std::string apiKey;
    try {
        apiKey = ApiKeyGenerator::generate();
    } catch (const std::exception& e) {
        errorCallback(std::string("ApiKeyGenerator failed: ") + e.what());
        return;
    }

    repo_->save(
        request.serviceName,
        request.targetUrl,
        apiKey,
        [callback = std::move(callback), apiKey](Backend backend) {
            callback(RegistrationResult{ std::move(backend), apiKey });
        },
        std::move(errorCallback)
    );
}

void RegistrationService::listBackends(
    std::function<void(std::vector<Backend>)>&& callback,
    std::function<void(const std::string&)>&& errorCallback)
{
    repo_->findAll(std::move(callback), std::move(errorCallback));
}

void RegistrationService::deactivateBackend(
    int id,
    std::function<void()>&& callback,
    std::function<void(const std::string&)>&& errorCallback)
{
    repo_->deactivate(id, std::move(callback), std::move(errorCallback));
}
