#ifndef RECON_TRACKER_H
#define RECON_TRACKER_H

#include <stdint.h>
#include <stddef.h>

struct recon_tracker_ctx {
    int dynamic_bans_fd;
    int threat_intel_fd;
};

// Callback for the ring buffer
int handle_recon_event(void *ctx, void *data, size_t data_sz);

// Called periodically from the main loop to regenerate tokens and clear old IPs
void age_recon_tracker(int dynamic_bans_fd);

#endif // RECON_TRACKER_H
