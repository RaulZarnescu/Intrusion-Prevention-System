#include <stddef.h>

#include "doh_resolver_blocklist.h"
#include "domain_set.h"

static struct domain_set *g_set = NULL;

int load_doh_resolver_blocklist(const char *filepath) {
    if (!g_set) {
        g_set = domain_set_create();
        if (!g_set) return -1;
    }
    return domain_set_load(g_set, filepath);
}

int doh_resolver_blocklist_contains(const char *domain) {
    return g_set ? domain_set_contains(g_set, domain) : 0;
}
