cmake_minimum_required(VERSION 3.16)
project(webhawk_middleware CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Drogon CONFIG REQUIRED)

file(GLOB_RECURSE SOURCES
    "src/routes/*.cc"
    "src/services/*.cc"
    "src/repositories/*.cc"
    "src/utils/*.cc"
)

add_executable(middleware main.cc ${SOURCES})
target_link_libraries(middleware PRIVATE Drogon::Drogon)
