cmake_minimum_required(VERSION 3.16)
project(WebHawk CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(security-engine)
add_subdirectory(middleware)
add_subdirectory(vulnerable-backend)
