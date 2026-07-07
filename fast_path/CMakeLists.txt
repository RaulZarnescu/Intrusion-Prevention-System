# Tell CMake to compile main.c into an executable named 'ips_loader'
add_executable(ips_loader main.c)

# Link the required eBPF libraries
target_link_libraries(ips_loader bpf elf z)