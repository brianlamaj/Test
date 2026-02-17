cmake_minimum_required(VERSION 3.24)
project(pwman LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(unofficial-sodium CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

add_library(pwman_core src/vault.cpp)
target_include_directories(pwman_core PUBLIC include)
target_link_libraries(pwman_core PUBLIC unofficial-sodium::sodium nlohmann_json::nlohmann_json)

add_executable(pwman src/main.cpp)
target_link_libraries(pwman PRIVATE pwman_core)

include(CTest)
if(BUILD_TESTING)
  add_executable(crypto_tests tests/crypto_tests.cpp)
  target_link_libraries(crypto_tests PRIVATE pwman_core)
  add_test(NAME crypto_tests COMMAND crypto_tests)
endif()
