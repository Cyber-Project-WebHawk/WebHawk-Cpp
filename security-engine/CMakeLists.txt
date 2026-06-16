cmake_minimum_required(VERSION 3.16)
project(security_engine CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Drogon CONFIG REQUIRED)

file(GLOB_RECURSE SOURCES
    "src/routes/*.cc"
    "src/services/*.cc"
    "src/repositories/*.cc"
)

add_executable(security_engine main.cc ${SOURCES})
target_link_libraries(security_engine PRIVATE Drogon::Drogon)
