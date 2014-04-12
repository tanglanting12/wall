#include <string.h>

#include "gtk_win_view.h"
#include "common_tools.h"

void process_text(char *dst, char *src, char *scat)
{
	strncpy(dst, src, strlen(src));
	strncat(dst, scat, strlen(scat));
}

char* get_network_info(char *info, char *name)
{
	char addr[50] = {'\0'};
	// char name[50] = {'\0'};
	char *status[4] = {
		"无线网络已链接 IP: ", 
		"有线网络已链接 IP: ",
		"网络已经链接",
		"网络未链接"
	};
	// net_status_t type = net_status(addr);
	net_status_t type = network_infos(name, addr);
	switch(type)
	{
		case NETWORK_ETH_AVAIL:
			process_text(info, status[1], addr);
			break;
		case NETWORK_WLAN_AVAIL:
			process_text(info, status[0], addr);
			break;
		case NETWORK_AVAIL:
			process_text(info, status[2], addr);
			break;
		case NETWORK_DIS_AVAIL:
		case NETWORK_ERROR:
			process_text(info, status[3], '\0');
			break;
		default:
			break;
	}
	return info;
}


int main(int argc, char **argv)
{
	char info[100] = {'\0'};
	char device_name[20] = {'\0'};
	get_network_info(info, device_name);
	init_views(argc, argv, info, device_name);
	printf("Main Eixt\n");
	return 0;
}
