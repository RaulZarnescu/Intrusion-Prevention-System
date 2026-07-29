find_program(CLANG_BIN clang)
find_program(BPFTOOL_BIN bpftool)
if(NOT CLANG_BIN)
    message(FATAL_ERROR "clang not found - required to compile ips.bpf.c")
endif()
if(NOT BPFTOOL_BIN)
    message(FATAL_ERROR "bpftool not found - required to generate ips.skel.h")
endif()

# main.c includes the generated skeleton "ips.skel.h", which does not live in
# source control (see .gitignore) and must be produced before main.c builds:
# ips.bpf.c -> ips_bpf.o (BPF bytecode) -> ips.skel.h (libbpf skeleton header)
set(BPF_SRC ${CMAKE_CURRENT_SOURCE_DIR}/ips.bpf.c)
set(BPF_OBJ ${CMAKE_CURRENT_BINARY_DIR}/ips_bpf.o)
set(BPF_SKEL ${CMAKE_CURRENT_BINARY_DIR}/ips.skel.h)

add_custom_command(
    OUTPUT ${BPF_OBJ}
    COMMAND ${CLANG_BIN} -g -O2 -target bpf -I${CMAKE_CURRENT_SOURCE_DIR} -c ${BPF_SRC} -o ${BPF_OBJ}
    DEPENDS ${BPF_SRC} ${CMAKE_CURRENT_SOURCE_DIR}/vmlinux.h ${CMAKE_CURRENT_SOURCE_DIR}/ips_fast_common.h
    COMMENT "Compiling eBPF program ips.bpf.c -> ips_bpf.o"
    VERBATIM
)

add_custom_command(
    OUTPUT ${BPF_SKEL}
    COMMAND sh -c "${BPFTOOL_BIN} gen skeleton ${BPF_OBJ} > ${BPF_SKEL}"
    DEPENDS ${BPF_OBJ}
    COMMENT "Generating BPF skeleton header ips.skel.h"
    VERBATIM
)

add_custom_target(ips_bpf_skeleton DEPENDS ${BPF_SKEL})

# Tell CMake to compile main.c into an executable named 'ips_loader'
add_executable(ips_loader main.c threat_intel.c)
add_dependencies(ips_loader ips_bpf_skeleton)
target_compile_options(ips_loader PRIVATE -g)
target_include_directories(ips_loader PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
# Link the required eBPF libraries
target_link_libraries(ips_loader bpf elf z)

# Standalone control-plane tool: injects threats.txt into the pinned blocklist map
# while ips_loader is running (e.g. a daily cron re-injection).
add_executable(ips_injector injector.c threat_intel.c)
target_compile_options(ips_injector PRIVATE -g)
target_link_libraries(ips_injector bpf elf z)
