#ifndef IPS_SLOW_PATH_H
#define IPS_SLOW_PATH_H

struct sniffer_args {
    int allowlist_fd;
    int blocklist_fd;
    int tracker_fd;
    int ifindex; // interface to bind the raw socket to
};

// Runs as a pthread per interface (see start_sniffer_thread() in fast_path/main.c).
// Sniffs raw packets via AF_PACKET, does TCP-flag anomaly detection and the "5 clean
// observations -> trust" greylist bootstrap, and populates the allowlist map directly.
void *slow_path_sniffer(void *arg);

#endif /* IPS_SLOW_PATH_H */
