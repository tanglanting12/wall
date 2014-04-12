#ifndef _NETFILTER_UTILS_
#define _NETFILTER_UTILS_

#define SUCCESS 1
#define FAILED 0
#define ALL_PROTO 0

#include "netcap.h"

static char *FILTER_TABLE = "filter";
static char *NAT_TABLE = "nat";
static char *MANGLE_TABLE = "mangle";
static char *INPUT_CHAIN = "INPUT";
static char *OUTPUT_CHAIN = "OUTPUT";
static char *FORWARD_CHAIN = "FORWARD";
static char *PRE_ROUTING_CHAIN = "PREROUTING";
static char *POST_ROUTING_CHAIN = "POSTROUTING";
static char *ACTION_ACCEPT = "ACCEPT";
static char *ACTION_DROP = "DROP";
static char *ACTION_REJECT = "REJECT";
static char *ACTION_DNAT = "DNAT";
static char *ACTION_SNAT = "SNAT";

/**
 * %F_HEAD:
 * %F_NO_HEAD:
 */
typedef enum {
	F_HEAD,
	F_NO_HEAD
} h_flag;

/**
 * %src_ip:
 * %src_port:
 * %dst_ip:
 * %dst_port:
 * %nat_minip: min ip of the nat table rule
 * %nat_maxip: max ip of the nat table rule
 * %proto:     icmp/tcp/udp
 * %chain:     the ip belone to which chain
 * %action:    DROP/ACCEPT/REJECT
 */
struct ip_data {
	int index;
	char src_ip[20];
	char src_port[15];
	char dst_ip[20];
	char dst_port[15];
	char nat_minip[20];
	char nat_maxip[20];
	int proto;
	char chain[30];
	char action[10];
	char table[10];
};

typedef struct ip_data_link {
	struct ip_data ip;
	struct ip_data_link *next;
} ip_link_t;

/**
 * add/delete the chain to the table
 * @table_name: which table to add
 * @chain_name: the name of the chain
 * @return:     1(success), 0(failed)
 */
int add_chain(char *table_name, char *chain_name);
int delete_chain(char *table_name, char *chain_name);

/**
 * add rule to the table
 * @table_name: table which to add
 * @chain_name: chain name
 * @inface:     the driver's interface
 * @proto:      TCP/UDP/ICMP...
 * @src_ip:     source ip address
 * @src_port:   source ip port, want to set all ports,use -1
 * @tar_ip:     target ip address
 * @tar_port:   target ip port, want to set all ports,use -1
 * @tar_action: DROP/REJECT/ACCEPT
 * @flag:       insert to head or append to the tail, h_flag = head flag
 * @return:     1(success), 0(failed)
 * @NOTE:       just support the action DROP, REJECT, ACCEPT
 */
int add_rule(char *table_name, 
		char *chain_name,
		char *inface,
		int proto,
		char *src_ip,
		int src_port,
		char *dst_ip, 
		int dst_port,
		char *tar_action,
		h_flag flag);

int add_rule2(char *table_name,
		char *chain_name,
		char *inface,
		int proto,
		char *src_ip,
		char *dst_ip,
		char *tar_action,
		h_flag flag);

/** 
 * table_name must be 'nat'
 * 
 * @NOTE: just support the target action: SNAT, DNAT,
 *        and the chains of OUTPUT, PREROUTING
 */
int add_nat_rule(char *chain_name,
		char *inface,
		int proto,
		char *src_ip,
		int src_port,
		char *dst_ip,
		int dst_port,
		char *nat_min_ip,
		int nat_min_port,
		char *nat_max_ip,
		int nat_max_port,
		char *tar_action,
		h_flag flag);

/**
 * delete the rule in chain
 * @table_name:
 * @chain_name:
 * @index:      the index of the chain, start from 0..
 * @return:     1(success), 0(failed)
 */
int delete_rule_at_index(
		char *table_name, 
		char *chain_name,
		int index);

/** 
 * flush the chains
 * @table_name: same as other func
 * @chain_name:
 * @return:     1(success), 0(failed)
 */
int flush_chain(char *table_name, char *chain_name);

/** 
 * get ip data links, if no more data return NULL
 * @return: the struct of ip datas, must be free after used
 */
ip_link_t* get_ip_all();

/** 
 * get ip datas by pass the table_name, include all chains 
 * @return: the struct of ip datas, must be free after used
 */
ip_link_t* get_ip_by_table(char *table_name);

/**
 * get ip datas by pass the table_name and chain_name 
 * @return: the struct of ip datas, must be free after used
 */
ip_link_t* get_ip_by_table_chain(const char *table_name, 
		const char *chain_name);

/** free the ip link struct */
void free_ip_link(ip_link_t *head);

#endif
