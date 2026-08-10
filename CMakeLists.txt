cmake_minimum_required(VERSION 3.10)
project(Intrusion_Prevention_System)

set(CMAKE_CXX_STANDARD 14)

# Tell CMake to go look inside the inline_bpf folder and run the CMakeLists.txt there
add_subdirectory(inline_bpf)