#ifndef IPS_CONFIG_H
#define IPS_CONFIG_H

// ==============================================================================
// INTRUSION PREVENTION SYSTEM - MASTER CONFIGURATION
// ==============================================================================

// Comment out the next line to switch to PRODUCTION mode
#define IPS_DEBUGGING

#ifdef IPS_DEBUGGING
    // --- TESTING SETTINGS ---
    #define RATE_PPS 5                  // Tokens added per second
    #define BURST_TOKENS 10             // Maximum bucket capacity
    #define MAX_TOLERATED_DROPS 15      // Packets dropped before banning
    #define AGING_THRESHOLD 60          // Seconds until an IP is unbanned
#else
    // --- PRODUCTION SETTINGS ---
    #define RATE_PPS 100
    #define BURST_TOKENS 50
    #define MAX_TOLERATED_DROPS 200
    #define AGING_THRESHOLD 86400       // 24 hours
#endif

// ==============================================================================
// STORAGE CONFIGURATION
// ==============================================================================

#define IPS_SAVE_DIR "../data"
#define CSV_FILE "../data/blocklist.csv"
#define CSV_TEMP "../data/blocklist_temp.csv"

// Calculated values (Do not edit)
#define ONE_SECOND_NS 1000000000ULL // Define 1 second in nanoseconds (1 billion)
#define REFILL_INTERVAL_NS (ONE_SECOND_NS / RATE_PPS)

// Standard Ethernet protocol types
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#endif /* IPS_CONFIG_H */