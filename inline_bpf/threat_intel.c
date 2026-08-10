#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>            // Required for bpf_map_update_elem
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include "ips_fast_common.h"
#include "threat_intel.h"

int inject_threat_intel(const char *filepath, int static_blocklist_fd) {
    FILE *file = fopen(filepath, "r");
    if (!file) {
        perror("[!] Failed to open Threat Intel file");
        return -1;
    }

    char line[256];
    int injected_count = 0;

    printf("[i] Parsing and injecting IPs from %s...\n", filepath);

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\r\n")] = 0; // Strip newlines


        if (line[0] == '\0' || line[0] == '#') continue; // Skip empty lines and comments

        // CIDR SPLITTER
        char *slash = strchr(line, '/');
        __u32 prefix = 32;

        if (slash != NULL) {
            *slash = '\0';
            prefix = atoi (slash + 1); // convert the numbers after '\'
        }

        // STRING TO BINARY: Convert the IP string
        struct in_addr parsed_ip;
        if (inet_pton(AF_INET, line, &parsed_ip) != 1) {
            fprintf(stderr, "[-] Warning: Skipping invalid IP format: %s\n", line);
            continue;
        }

        // ASSEMBLE THE EBPF STRUCTS
        struct lpm_ip_key key = {
            .prefixlen = prefix,
            .ip = parsed_ip.s_addr
        };


        struct ips_blocklist_data value = {
            .ban_timestamp = time (NULL),
            .is_static = 1
        };

        // Kernel Injector
        if (bpf_map_update_elem(static_blocklist_fd, &key, &value, BPF_ANY) == 0) {
            injected_count++;
        }else {
            fprintf(stderr, "[-] Failed to inject %s / %u\n", line, prefix);
        }
    }

    fclose(file);
    return injected_count;
}
