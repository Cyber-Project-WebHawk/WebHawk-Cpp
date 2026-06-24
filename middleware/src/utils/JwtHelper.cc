#include "JwtHelper.h"

#include <jwt-cpp/jwt.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace {
constexpr char kIssuer[]      = "webhawk";
constexpr char kTypeAccess[]  = "access";
}

const std::string& JwtHelper::secret() {
    // Read once and cache. Throwing here (rather than using a weak default) prevents
    // accidentally signing tokens with a guessable key in production.
    static const std::string value = []() -> std::string {
        const char* env = std::getenv("JWT_SECRET");
        if (!env || std::string(env).empty()) {
            throw std::runtime_error("JwtHelper: JWT_SECRET environment variable is not set");
        }
        return std::string(env);
    }();
    return value;
}

std::string JwtHelper::createAccessToken(int userId,
                                         const std::string& email,
                                         const std::string& role) {
    const auto now = std::chrono::system_clock::now();
    return jwt::create()
        .set_issuer(kIssuer)
        .set_type("JWS")
        .set_subject(std::to_string(userId))
        .set_payload_claim("email", jwt::claim(email))
        .set_payload_claim("role", jwt::claim(role))
        .set_payload_claim("type", jwt::claim(std::string(kTypeAccess)))
        .set_issued_at(now)
        .set_expires_at(now + ACCESS_TOKEN_TTL)
        .sign(jwt::algorithm::hs256{secret()});
}

JwtHelper::AccessToken JwtHelper::verifyAccessToken(const std::string& token) {
    AccessToken result;
    try {
        auto decoded = jwt::decode(token);

        jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{secret()})
            .with_issuer(kIssuer)
            .verify(decoded); // throws on bad signature / expiry

        if (!decoded.has_payload_claim("type") ||
            decoded.get_payload_claim("type").as_string() != kTypeAccess) {
            return result; // refresh tokens (or anything else) are not valid here
        }

        result.userId = std::stoi(decoded.get_subject());
        result.email  = decoded.has_payload_claim("email")
                            ? decoded.get_payload_claim("email").as_string()
                            : "";
        result.role   = decoded.has_payload_claim("role")
                            ? decoded.get_payload_claim("role").as_string()
                            : "user";
        result.valid  = true;
    } catch (const std::exception&) {
        result.valid = false;
    }
    return result;
}

std::string JwtHelper::generateRefreshToken() {
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (!urandom) {
        throw std::runtime_error("JwtHelper: failed to open /dev/urandom");
    }

    unsigned char bytes[32];
    urandom.read(reinterpret_cast<char*>(bytes), sizeof(bytes));
    if (!urandom) {
        throw std::runtime_error("JwtHelper: failed to read random bytes");
    }

    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (unsigned char b : bytes) {
        hex << std::setw(2) << static_cast<unsigned int>(b);
    }
    return hex.str(); // 64 hex chars
}

std::string JwtHelper::sha256Hex(const std::string& input) {
    unsigned char digest[SHA256_DIGEST_LENGTH];

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("JwtHelper: EVP_MD_CTX_new failed");
    }

    unsigned int len = 0;
    bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
              EVP_DigestUpdate(ctx, input.data(), input.size()) == 1 &&
              EVP_DigestFinal_ex(ctx, digest, &len) == 1;
    EVP_MD_CTX_free(ctx);

    if (!ok) {
        throw std::runtime_error("JwtHelper: SHA-256 digest failed");
    }

    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < len; ++i) {
        hex << std::setw(2) << static_cast<unsigned int>(digest[i]);
    }
    return hex.str();
}
