#include <stdio.h>
#include <bpf/bpf.h>            // Required for bpf_obj_get
#include "threat_intel.h"
#include "../config.h"

int main(int argc, char **argv) {

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path_to_threat_intel.txt>\n", argv[0]);
        return 1;
    }

    int static_blocklist_fd = bpf_obj_get(STATIC_BLOCKLIST_PIN_PATH);

    if (static_blocklist_fd < 0) {
        fprintf(stderr, "[!] Error: Could not find pinned map at %s.\n", STATIC_BLOCKLIST_PIN_PATH);
        fprintf(stderr, "Please check that the main IPS daemon is running. \n");
        return 1;
    }

    printf("[+] Successfully connected to kernel static blocklist! (FD: %d)\n", static_blocklist_fd);

    int total_injected = inject_threat_intel(argv[1], static_blocklist_fd);

    if (total_injected >= 0) {
        printf("[+] Threat Intel Injection Complete. Added %d static rules.\n", total_injected);
    }

    return 0;
}