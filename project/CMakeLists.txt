cmake_minimum_required(VERSION 3.0.0)
project(sha VERSION 0.1.0)
set(ENTRYPOINT sha)

set(CMAKE_BUILD_TYPE Debug)

include_directories(include)

file(GLOB SOURCES "source/*.c")
add_executable(${ENTRYPOINT} ${SOURCES})

if (MSVC)
	target_compile_options(${ENTRYPOINT} PRIVATE /W4 /WX)
endif()
