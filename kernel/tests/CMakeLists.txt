cmake_minimum_required(VERSION 3.14)

set(CMAKE_C_FLAGS_RELEASE "-O1 -g2")
set(CMAKE_C_FLAGS_DEBUG "-O0 -g")

file(GLOB OBJECT_SOURCE "*.c")
add_library(${PROJECT_NAME}-tests OBJECT ${OBJECT_SOURCE})
target_include_directories(
	${PROJECT_NAME}-tests
	PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
