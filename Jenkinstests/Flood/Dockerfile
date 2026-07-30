FROM debian:bookworm-slim

# Runtime-only deps for the flood test: `ip` command, Python+scapy for the
# flood, and the shared libs ips_loader is dynamically linked against
# (bpf/elf/z) - no compiler needed, the binary is already built by the
# Jenkins "Build" stage before this image ever runs.
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 python3 python3-pip sudo libbpf1 libelf1 zlib1g \
    && pip3 install --no-cache-dir scapy \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
