cmake_minimum_required(VERSION 3.22)
project(urovdetect LANGUAGES C CXX)

set(lab "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(Plugin.SymbolResolver OFF CACHE BOOL "Dobby symbol resolver for the test app" FORCE)
add_subdirectory("${lab}/Dobby" dobby EXCLUDE_FROM_ALL)

add_library(urovdetect SHARED app.c "${lab}/native/urov_detect.c" "${lab}/native/urov_observe.c")
target_include_directories(urovdetect PRIVATE "${lab}/native")
set_target_properties(urovdetect PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)
target_compile_options(urovdetect PRIVATE
    -O2 -g0 -Wall -Wextra -Werror -Wformat=2 -Wshadow -fno-omit-frame-pointer -pthread)
target_link_options(urovdetect PRIVATE
    -pthread -Wl,--build-id=sha1 -Wl,-z,noexecstack -Wl,-z,max-page-size=16384
    -Wl,--exclude-libs,libdobby.a)
target_link_libraries(urovdetect PRIVATE dobby_static log dl z)
