#include <stdio.h>
#include <bpf/bpf.h>            // Required for bpf_obj_get
#include "threat_intel.h"

int main(int argc, char **argv) {

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path_to_threat_intel.txt>\n", argv[0]);
        return 1;
    }

    const char *pin_path = "/sys/fs/bpf/ips_blocklist"; //the path defined in main.c
    int blocklist_fd = bpf_obj_get(pin_path);

    if (blocklist_fd < 0) {
        fprintf(stderr, "[!] Error: Could not find pinned map at %s.\n", pin_path);
        fprintf(stderr, "Please check that the main IPS daemon is running. \n");
        return 1;
    }

    printf("[+] Successfully connected to kernel Blocklist! (FD: %d)\n", blocklist_fd);

    int total_injected = inject_threat_intel(argv[1], blocklist_fd);

    if (total_injected >= 0) {
        printf("[+] Threat Intel Injection Complete. Added %d static rules.\n", total_injected);
    }

    return 0;
}