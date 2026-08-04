#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>

#include "domain_set.h"

// Open-addressing string table, sized to a 2x load factor on load. Reload builds a fresh
// table off to the side and swaps the active pointer under set->lock -- lookups only ever
// see a fully-built table, and only block for the swap itself, not for the (possibly slow)
// parse of a large feed file.
struct table {
    char **slots;
    size_t capacity;
    size_t count;
};

struct domain_set {
    struct table *active;
    pthread_mutex_t lock;
};

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

static void table_free(struct table *table) {
    if (!table) return;
    for (size_t i = 0; i < table->capacity; i++) {
        free(table->slots[i]);
    }
    free(table->slots);
    free(table);
}

static void table_insert(struct table *table, const char *domain) {
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

static int table_contains(const struct table *table, const char *domain) {
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

struct domain_set *domain_set_create(void) {
    struct domain_set *set = malloc(sizeof(*set));
    if (!set) return NULL;
    set->active = NULL;
    pthread_mutex_init(&set->lock, NULL);
    return set;
}

int domain_set_load(struct domain_set *set, const char *filepath) {
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        fprintf(stderr, "[!] Failed to open domain list %s: %s\n", filepath, strerror(errno));
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
        fprintf(stderr, "[!] Domain list %s has no entries -- keeping previous list\n", filepath);
        return -1;
    }

    size_t capacity = 1;
    while (capacity < entry_count * 2) capacity <<= 1;

    struct table *new_table = malloc(sizeof(*new_table));
    if (!new_table) {
        fclose(fp);
        fprintf(stderr, "[!] Failed to allocate domain set table: %s\n", strerror(errno));
        return -1;
    }
    new_table->slots = calloc(capacity, sizeof(char *));
    if (!new_table->slots) {
        fclose(fp);
        fprintf(stderr, "[!] Failed to allocate domain set slots: %s\n", strerror(errno));
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

    pthread_mutex_lock(&set->lock);
    struct table *old_table = set->active;
    set->active = new_table;
    pthread_mutex_unlock(&set->lock);

    table_free(old_table);

    printf("[i] Loaded %zu domains from %s\n", new_table->count, filepath);
    return (int)new_table->count;
}

int domain_set_contains(struct domain_set *set, const char *domain) {
    char lower[256];
    strncpy(lower, domain, sizeof(lower) - 1);
    lower[sizeof(lower) - 1] = '\0';
    lowercase_inplace(lower);

    pthread_mutex_lock(&set->lock);
    int found = table_contains(set->active, lower);
    pthread_mutex_unlock(&set->lock);
    return found;
}
