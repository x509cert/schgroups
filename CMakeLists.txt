cmake_minimum_required(VERSION 3.31)
project(schgroups LANGUAGES CXX)

if(NOT MSVC)
  message(FATAL_ERROR "Build with MSVC (VS 2026 / v145).")
endif()

# Reusable group-control module (no I/O); link it into other Schannel projects.
add_library(schannel_groups STATIC schannel_groups.cpp schannel_groups.h)
target_include_directories(schannel_groups PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(schannel_groups PUBLIC UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
target_compile_options(schannel_groups PRIVATE /std:c++latest /permissive- /utf-8 /EHsc /W4 /sdl /guard:cf /wd4865)
target_link_libraries(schannel_groups PUBLIC secur32 crypt32 ncrypt advapi32)
set_property(TARGET schannel_groups PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(schgroups schgroups.cpp)
target_link_libraries(schgroups PRIVATE schannel_groups)

target_compile_definitions(schgroups PRIVATE
  UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)

target_compile_options(schgroups PRIVATE
  /std:c++latest /permissive- /Zc:__cplusplus /utf-8 /EHsc /W4 /sdl /guard:cf
  /wd4865)  # SDK-header conformance warning under MSVC 19.50 /Wall

target_link_options(schgroups PRIVATE /guard:cf /CETCOMPAT /DYNAMICBASE /NXCOMPAT)

target_link_libraries(schgroups PRIVATE ws2_32 secur32 crypt32 ncrypt bcrypt advapi32)

set_property(TARGET schgroups PROPERTY
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
