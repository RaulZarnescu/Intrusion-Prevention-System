#ifndef IPS_THREAT_INTEL_H
#define IPS_THREAT_INTEL_H

// Parses an IP/CIDR threat-intel list (one entry per line, '#' comments allowed)
// and injects each as a static (is_static=1) entry into the given blocklist map fd.
// Returns the number of entries injected, or -1 if the file couldn't be opened.
int inject_threat_intel(const char *filepath, int static_blocklist_fd);

#endif /* IPS_THREAT_INTEL_H */
