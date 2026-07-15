# Tell CMake to compile main.c into an executable named 'ips_loader'
add_executable(ips_loader main.c)
target_compile_options(ips_loader PRIVATE -g)
# Link the required eBPF libraries
target_link_libraries(ips_loader bpf elf z)