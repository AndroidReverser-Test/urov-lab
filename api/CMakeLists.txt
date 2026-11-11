cmake_minimum_required(VERSION 3.16)
project(urov_user_api VERSION 1.0.0 LANGUAGES C)

add_library(urov STATIC src/urov.c)
target_include_directories(urov PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(urov PUBLIC c_std_11)
set_target_properties(urov PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_options(urov PRIVATE -Wall -Wextra -Werror)

add_executable(urov-query examples/query.c)
target_link_libraries(urov-query PRIVATE urov)
target_link_options(urov-query PRIVATE -Wl,-z,max-page-size=16384)
