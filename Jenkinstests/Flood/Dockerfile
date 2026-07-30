FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 python3 python3-pip sudo libbpf1 libelf1 zlib1g \
    && pip3 install --no-cache-dir --break-system-packages scapy \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
