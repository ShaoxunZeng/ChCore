include_directories("..")
include_directories("../lib")

add_subdirectory(tmpfs)
add_subdirectory(apps)

set(CMAKE_C_FLAGS_RELEASE "-O1 -g2")
set(CMAKE_C_FLAGS_DEBUG "-O0 -g")