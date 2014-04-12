#ifndef _NET_CAP_
#define _NET_CAP_

#include <pcap.h>

static pcap_t *descr = NULL;

/**
 * %src_ip: the src ip
 * %dst_ip: the dst ip
 * %proto:  protocols
 * %len:    the length of the data
 */
typedef struct {
	char src_ip[20];
	char dst_ip[20];
	char proto[10];
	int len;
} netcap_t;

/**
 * init the net cap
 * @device: the device name which to cap
 * @return: 0 failed, 1 success
 */
int cap_init(const char *device);

/** 
 * get the connect info
 * @return: the netcap of the 
 */
void get_netcap(netcap_t *info);

/** free the resource */
void cap_close();

#endif
