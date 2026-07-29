# Tell CMake to compile main.c into an executable named 'ips_loader'
add_executable(ips_loader main.c threat_intel.c)
target_compile_options(ips_loader PRIVATE -g)
# Link the required eBPF libraries
target_link_libraries(ips_loader bpf elf z)

# Standalone control-plane tool: injects threats.txt into the pinned blocklist map
# while ips_loader is running (e.g. a daily cron re-injection).
add_executable(ips_injector injector.c threat_intel.c)
target_compile_options(ips_injector PRIVATE -g)
target_link_libraries(ips_injector bpf elf z)

# TODO add check for required libraries and host system