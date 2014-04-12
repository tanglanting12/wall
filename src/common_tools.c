#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include "common_tools.h"

// @FIXME ugly code
// get the net work status and ip address
net_status_t net_status(char *addr)
{
	FILE *fp;
	struct ifreq ifr;
	struct ethtool_value value;
	char buf[512] = {'\0'};
	char eth_name[10] = {'\0'};
	char wlan_name[10] = {'\0'};
	char *token = NULL;
	char *_addr;
	int fd;

	bzero(&ifr, sizeof(struct ifreq));
	bzero(&value, sizeof(struct ethtool_value));

	// get network driver address from '/proc/net/dev'
	if ((fp = fopen("/proc/net/dev", "r")) != NULL)
	{
		while(fgets(buf, sizeof(buf), fp) != NULL)
		{
			// eth0 eth1 ..ect
			if(strstr(buf, "eth") != NULL)
			{
				token = strtok(buf, ":");  
				while (*token == ' ') 
				{
					++token;
				}
				strncpy(eth_name, token, strlen(token));  
			}
			// wlan0 wlan1 ..ect
			if(strstr(buf, "wlan") != NULL)
			{
				token = strtok(buf, ":");
				while(*token == ' ')
				{
					++ token;
				}
				strncpy(wlan_name, token, strlen(token));
			}   
		}   
	} 
	else 
	{
		perror(">>> can not open the /proc/net/dev");
		addr = NULL;
		fclose(fp);
		return NETWORK_ERROR;
	}
	fclose(fp);
	printf("%s - %s\n", eth_name, wlan_name);
	// TODO to write the log
	if((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		perror(">>> request ifreq failed");
		addr = NULL;
		close(fd);
		return NETWORK_ERROR;
	}
	value.cmd = ETHTOOL_GLINK;
	ifr.ifr_data = (caddr_t) &value;
	// eth addr
	strncpy(ifr.ifr_name, eth_name, sizeof(ifr.ifr_name) - 1);
	// need the root permission
	if(ioctl(fd, SIOCETHTOOL, &ifr) == -1)
	{
		perror("EthTool failed");
	}
	if(value.data)
	{
		ioctl(fd, SIOCGIFADDR, &ifr);
		_addr = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
		strncpy(addr, _addr, strlen(_addr));
		close(fd);
		return NETWORK_ETH_AVAIL;
	}
	// wlan addr
	strncpy(ifr.ifr_name, wlan_name, sizeof(ifr.ifr_name) - 1);
	if(ioctl(fd, SIOCETHTOOL, &ifr) == -1)
	{
		perror("EthTool failed");
	}
	if(value.data)
	{
		ioctl(fd, SIOCGIFADDR, &ifr);
		_addr = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
		strncpy(addr, _addr, strlen(_addr));
		close(fd);
		return NETWORK_WLAN_AVAIL;
	}
	addr = NULL;
	return NETWORK_DIS_AVAIL;
}


net_status_t network_infos(char *d_name, char *addr)
{
	struct ifconf ifc;
	struct ifreq req[16];
	int fd;
	int d_size, i;
	char *local_ip = "127.0.0.1";
	net_status_t type = NETWORK_DIS_AVAIL;

	if((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror(">>> network_inf -> socket");
		close(fd);
		type = NETWORK_ERROR;
		return type;
	}

	ifc.ifc_len = sizeof(req);
	ifc.ifc_buf = (caddr_t) req;
	if(!ioctl(fd, SIOCGIFCONF, &ifc))
	{
		d_size = ifc.ifc_len / sizeof(struct ifreq);
		for(i = 0; i < d_size; ++i)
		{
			char *t_addr = inet_ntoa(((struct sockaddr_in *)
						&ifc.ifc_req[i].ifr_addr)->sin_addr);
			char *t_name = ifc.ifc_req[i].ifr_name;
			printf(">>> network interface %s, addr:%s\n", t_name, t_addr);
			// if equal to the localhost, not process
			if(strcmp(t_addr, local_ip))
			{
				strncpy(d_name, t_name, strlen(t_name));
				strncpy(addr, t_addr, strlen(t_addr));
				d_name[strlen(t_name)] = '\0';
				addr[strlen(t_addr)] = '\0';
				type = network_type(d_name);
				break;
			}
		}
	}
	close(fd);
	return type;

}

net_status_t network_type(const char *d_name)
{
	char *eth = "eth";
	char *wlan = "wlan";
	if(!d_name)
	{
		return NETWORK_DIS_AVAIL;
	}

	if(strstr(d_name, eth) != NULL)
	{
		return NETWORK_ETH_AVAIL;
	}
	else if(strstr(d_name, wlan) != NULL)
	{
		return NETWORK_WLAN_AVAIL;
	}
	return NETWORK_AVAIL;
}

