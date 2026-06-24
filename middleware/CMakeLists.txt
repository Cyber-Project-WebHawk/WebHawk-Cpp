cmake_minimum_required(VERSION 3.16)
project(webhawk_middleware CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Drogon CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

# libsodium (Argon2id password hashing) via pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# jwt-cpp (header-only JWT) fetched at configure time
include(FetchContent)
FetchContent_Declare(
    jwt-cpp
    GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
    GIT_TAG        v0.7.0
)
set(JWT_BUILD_EXAMPLES OFF CACHE INTERNAL "")
set(JWT_BUILD_TESTS OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(jwt-cpp)

file(GLOB_RECURSE SOURCES
    "src/routes/*.cc"
    "src/services/*.cc"
    "src/repositories/*.cc"
    "src/utils/*.cc"
    "src/filters/*.cc"
)

add_executable(middleware main.cc ${SOURCES})

target_include_directories(middleware PRIVATE ${SODIUM_INCLUDE_DIRS})
target_link_libraries(middleware PRIVATE
    Drogon::Drogon
    OpenSSL::Crypto
    jwt-cpp::jwt-cpp
    ${SODIUM_LIBRARIES}
)
