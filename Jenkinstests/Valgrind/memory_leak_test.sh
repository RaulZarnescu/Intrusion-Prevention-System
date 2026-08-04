#!/bin/bash
# memory_leak_test.sh

set -e # Exit immediately if a command exits with a non-zero status

# Find where this script lives, go up to the project root, then step into the build folder
cd "$(dirname "$0")/../../build"

echo "========================================"
echo "[i] Starting Valgrind Memory Leak Test"
echo "========================================"

# Run the Valgrind test from inside the build directory
sudo timeout --preserve-status -s SIGTERM 10 \
    valgrind \
    --leak-check=full \
    --show-leak-kinds=definite,indirect \
    --errors-for-leak-kinds=definite \
    --undef-value-errors=no \
    --error-exitcode=100 \
    ./fast_path/ips_loader

echo "[+] Memory leak test passed successfully! No definite leaks detected."