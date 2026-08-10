#include <stdio.h>
#include <string.h>
#include <bpf/bpf.h>
#include "../inline_bpf/ips_fast_common.h"
#include "doh_resolver_blocklist.h"

int load_doh_resolver_blocklist(const char *filepath, int doh_map_fd) {
    FILE *f = fopen(filepath, "r");
    if (!f) return -1;
    
    char line[512];
    int count = 0;
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        
        char *newline = strchr(line, '\n');
        if (newline) *newline = '\0';
        
        struct sni_key key = {0};
        strncpy(key.sni, line, SNI_MAX_LEN - 1);
        
        __u8 dummy = 1;
        if (bpf_map_update_elem(doh_map_fd, &key, &dummy, BPF_ANY) == 0) {
            count++;
        }
    }
    
    fclose(f);
    printf("[i] Loaded %d DoH resolvers from %s into BPF map\n", count, filepath);
    return count;
}

int doh_resolver_blocklist_contains(const char *domain) {
    return 0; // Legacy function, no longer used
}
