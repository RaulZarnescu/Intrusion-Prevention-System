#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>            // Required for bpf_obj_get
#include "ips_fast_common.h"

int main(int argc, char *argv[]) {
    const char *pin_path = "/sys/fs/bpf/ips_blocklist"; //the path defined in main.c
    int blocklist_fd = bpf_obj_get(pin_path);

    if (blocklist_fd < 0) {
        fprintf(stderr, "[!] Error: Could not find pinned map at %s.\n", pin_path);
        fprintf(stderr, "Please check that the main IPS daemon is running. \n");
        return 1;
    }

    printf("[+] Successfully connected to kernel Blocklist! (FD: %d)\n", blocklist_fd);

    //TODO: Text parsing logic
    
    return 0;
}