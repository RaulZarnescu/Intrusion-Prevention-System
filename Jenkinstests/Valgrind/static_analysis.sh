#!/bin/bash
# 01_static_analysis.sh

set -e # Exit immediately if a command exits with a non-zero status

# Step back to the project root
cd "$(dirname "$0")/../.."

echo "========================================"
echo "[i] Starting Cppcheck Static Analysis"
echo "========================================"

# Run cppcheck, ignoring build/ and suppressing auto-generated eBPF files
cppcheck \
    --enable=warning,performance,portability,style \
    --error-exitcode=1 \
    --suppress=missingIncludeSystem \
    --suppress=*:fast_path/vmlinux.h \
    --suppress=*:fast_path/ips.skel.h \
    --suppress=constParameterCallback:fast_path/main.c \
    --suppress=constParameterPointer:slow_path/slow_path.c \
    --quiet \
    -i build/ \
    .

echo "[+] Static analysis passed! Code is clean."