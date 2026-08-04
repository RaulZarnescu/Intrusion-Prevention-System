#ifndef IPS_DOMAIN_SET_H
#define IPS_DOMAIN_SET_H

// Opaque handle for a thread-safe, reload-capable set of lowercased domain strings.
// Backs sni_blocklist.c and doh_resolver_blocklist.c -- each owns its own instance so
// their files/lifecycles/refresh triggers stay independent (a URLhaus-managed malware
// feed and a small hand-curated resolver list must never clobber each other on reload).
struct domain_set;

// Allocates an empty set. Returns NULL on allocation failure.
struct domain_set *domain_set_create(void);

// (Re)loads set from filepath, atomically replacing its contents -- domain_set_contains()
// never blocks on or sees a half-loaded table. Returns the number of domains loaded, or -1
// on failure (existing contents left intact).
int domain_set_load(struct domain_set *set, const char *filepath);

// Returns 1 if domain is in set, 0 otherwise. Thread-safe, callable from any thread.
int domain_set_contains(struct domain_set *set, const char *domain);

#endif /* IPS_DOMAIN_SET_H */
