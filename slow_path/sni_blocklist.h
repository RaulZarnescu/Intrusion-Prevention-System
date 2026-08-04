#ifndef IPS_SNI_BLOCKLIST_H
#define IPS_SNI_BLOCKLIST_H

// (Re)loads the SNI domain blocklist from filepath, atomically replacing whatever was
// loaded before -- sni_blocklist_contains() never blocks on or sees a half-loaded table.
// Returns the number of domains loaded, or -1 on failure (existing table left intact).
int load_sni_blocklist(const char *filepath);

// Returns 1 if domain is on the blocklist, 0 otherwise. Thread-safe, callable from any
// sniffer thread.
int sni_blocklist_contains(const char *domain);

#endif /* IPS_SNI_BLOCKLIST_H */
