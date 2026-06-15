cmake_minimum_required(VERSION 3.16)
project(webhawk_vulnerable CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Drogon CONFIG REQUIRED)

file(GLOB_RECURSE SOURCES
    "src/routes/*.cc"
)

add_executable(vulnerable_backend main.cc ${SOURCES})
target_link_libraries(vulnerable_backend PRIVATE Drogon::Drogon)
