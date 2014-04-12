#ifndef _COMMON_TOOLS_
#define _COMMON_TOOLS_

#define ETHTOOL_GLINK 0x0000000a

typedef enum {
	NETWORK_ETH_AVAIL,
	NETWORK_WLAN_AVAIL,
	NETWORK_AVAIL,
	NETWORK_DIS_AVAIL,
	NETWORK_ERROR
} net_status_t;

struct ethtool_value {
	int cmd;
	int data;
};

/** 
 * return the net work status 
 * also can get the addr by pass the parameter
 * @FIXME is to long and ugly
 */
net_status_t net_status(char *addr);

/** 
 * newly way to get addr info
 * @d_name:  the driver name
 * @addr:    the address of the driver
 */
net_status_t network_infos(char *d_name, char *addr);

/**
 * the user should be call the network_info
 * @d_name: network interface name
 */
net_status_t network_type(const char *d_name);

#endif
