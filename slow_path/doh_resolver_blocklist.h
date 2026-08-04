#ifndef IPS_DOH_RESOLVER_BLOCKLIST_H
#define IPS_DOH_RESOLVER_BLOCKLIST_H

// Same shape as sni_blocklist.h, backing a separate set: known DNS-over-HTTPS/DNS-over-TLS
// resolver hostnames. Kept independent of the malware SNI blocklist on purpose -- this one
// is a policy list (are DNS-enforcement bypass attempts allowed on this LAN?), hand-curated
// rather than fed by a threat-intel source, and a deployment may want one enforced without
// the other.
int load_doh_resolver_blocklist(const char *filepath);
int doh_resolver_blocklist_contains(const char *domain);

#endif /* IPS_DOH_RESOLVER_BLOCKLIST_H */
