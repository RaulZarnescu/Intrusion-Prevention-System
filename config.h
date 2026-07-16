#ifndef IPS_CONFIG_H
#define IPS_CONFIG_H

// ==============================================================================
// INTRUSION PREVENTION SYSTEM - MASTER CONFIGURATION
// ==============================================================================

// ==============================================================================
// STORAGE CONFIGURATION
// ==============================================================================

#define IPS_SAVE_DIR "../data"
#define CSV_FILE "../data/blocklist.csv"
#define CSV_TEMP "../data/blocklist_temp.csv"
#define CONFIG_FILE_PATH "../config/config.ini"

#define BATCH_SIZE 1024 // can be 2048 as raspberry pi has 64kb l1 cache for data



// Standard Ethernet protocol types
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#endif /* IPS_CONFIG_H */