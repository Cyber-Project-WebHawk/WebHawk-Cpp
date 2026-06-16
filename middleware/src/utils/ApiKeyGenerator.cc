#include "ApiKeyGenerator.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>

std::string ApiKeyGenerator::generate() {
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (!urandom) {
        throw std::runtime_error("ApiKeyGenerator: failed to open /dev/urandom");
    }

    unsigned char bytes[32];
    urandom.read(reinterpret_cast<char*>(bytes), sizeof(bytes));
    if (!urandom) {
        throw std::runtime_error("ApiKeyGenerator: failed to read 32 bytes from /dev/urandom");
    }

    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (unsigned char b : bytes) {
        hex << std::setw(2) << static_cast<unsigned int>(b);
    }

    return hex.str(); // always exactly 64 characters
}
