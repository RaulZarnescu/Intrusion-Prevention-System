#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>

#include "sni_blocklist.h"

// Open-addressing string set, sized to a 2x load factor on load. Reload builds a fresh
// table off to the side and swaps the active pointer under g_table_lock -- lookups from
// the sniffer threads only ever see a fully-built table, and only block for the swap
// itself, not for the (possibly slow) parse of a large feed file.
struct sni_table {
    char **slots;
    size_t capacity;
    size_t count;
};

static struct sni_table *g_active_table = NULL;
static pthread_mutex_t g_table_lock = PTHREAD_MUTEX_INITIALIZER;

static unsigned long fnv1a_hash(const char *s) {
    unsigned long h = 2166136261UL;
    for (; *s; s++) {
        h ^= (unsigned char)*s;
        h *= 16777619UL;
    }
    return h;
}

static void lowercase_inplace(char *s) {
    for (; *s; s++) *s = (char)tolower((unsigned char)*s);
}

static void table_free(struct sni_table *table) {
    if (!table) return;
    for (size_t i = 0; i < table->capacity; i++) {
        free(table->slots[i]);
    }
    free(table->slots);
    free(table);
}

static void table_insert(struct sni_table *table, const char *domain) {
    unsigned long h = fnv1a_hash(domain) % table->capacity;
    size_t start = h;
    while (table->slots[h]) {
        if (strcmp(table->slots[h], domain) == 0) return; // duplicate, ignore
        h = (h + 1) % table->capacity;
        if (h == start) return; // table sized with headroom above -- shouldn't happen
    }
    table->slots[h] = strdup(domain);
    if (table->slots[h]) table->count++;
}

static int table_contains(const struct sni_table *table, const char *domain) {
    if (!table || table->capacity == 0) return 0;
    unsigned long h = fnv1a_hash(domain) % table->capacity;
    size_t start = h;
    while (table->slots[h]) {
        if (strcmp(table->slots[h], domain) == 0) return 1;
        h = (h + 1) % table->capacity;
        if (h == start) break;
    }
    return 0;
}

int load_sni_blocklist(const char *filepath) {
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        fprintf(stderr, "[!] Failed to open SNI blocklist %s: %s\n", filepath, strerror(errno));
        return -1;
    }

    // First pass: count real entries so the table can be sized once (no rehashing).
    char line[256];
    size_t entry_count = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '\n' || *p == '#') continue;
        entry_count++;
    }

    if (entry_count == 0) {
        fclose(fp);
        fprintf(stderr, "[!] SNI blocklist %s has no entries -- keeping previous list\n", filepath);
        return -1;
    }

    size_t capacity = 1;
    while (capacity < entry_count * 2) capacity <<= 1;

    struct sni_table *new_table = malloc(sizeof(*new_table));
    if (!new_table) {
        fclose(fp);
        fprintf(stderr, "[!] Failed to allocate SNI blocklist table: %s\n", strerror(errno));
        return -1;
    }
    new_table->slots = calloc(capacity, sizeof(char *));
    if (!new_table->slots) {
        fclose(fp);
        fprintf(stderr, "[!] Failed to allocate SNI blocklist slots: %s\n", strerror(errno));
        free(new_table);
        return -1;
    }
    new_table->capacity = capacity;
    new_table->count = 0;

    rewind(fp);
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '#') continue;

        lowercase_inplace(p);
        table_insert(new_table, p);
    }
    fclose(fp);

    pthread_mutex_lock(&g_table_lock);
    struct sni_table *old_table = g_active_table;
    g_active_table = new_table;
    pthread_mutex_unlock(&g_table_lock);

    table_free(old_table);

    printf("[i] Loaded %zu domains into SNI blocklist from %s\n", new_table->count, filepath);
    return (int)new_table->count;
}

int sni_blocklist_contains(const char *domain) {
    char lower[256];
    strncpy(lower, domain, sizeof(lower) - 1);
    lower[sizeof(lower) - 1] = '\0';
    lowercase_inplace(lower);

    pthread_mutex_lock(&g_table_lock);
    int found = table_contains(g_active_table, lower);
    pthread_mutex_unlock(&g_table_lock);
    return found;
}
