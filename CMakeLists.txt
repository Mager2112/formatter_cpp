cmake_minimum_required(VERSION 3.10)
project(FormatterCpp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Для работы с сетью (libcurl)
find_package(CURL REQUIRED)

add_executable(formatter_cpp
    src/main.cpp
    src/formatter.cpp
    src/network.cpp
    src/utf8.cpp
)

target_include_directories(formatter_cpp PRIVATE ${CURL_INCLUDE_DIRS})
target_link_libraries(formatter_cpp ${CURL_LIBRARIES})

# Включение предупреждений (анализаторы это любят)
target_compile_options(formatter_cpp PRIVATE -Wall -Wextra -Wpedantic)