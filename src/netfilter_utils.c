#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netdb.h>

#include <linux/netfilter_ipv4/nf_nat.h>
#include "libiptc/libiptc.h"
#include "netfilter_utils.h"

static char *DEFAULT_IP = "0.0.0.0";

/** get the handle of the iptable */
struct iptc_handle* get_handle(const char *table_name)
{   
	struct iptc_handle *handle;
	if(!table_name) 
	{
		// table_name must not NULL
		table_name = (char*) FILTER_TABLE;
	}
	// init the handle of the table
	handle = iptc_init(table_name);
	if(!handle)
	{
		perror(">>> add_chain failed");
		return NULL;
	}
	return handle;
}

/** add chain to table, should use less */
int add_chain(char *table_name, char *chain_name)
{
	struct iptc_handle *handle = get_handle(table_name);
	int result = FAILED;
	if(!handle || !chain_name)
	{
		return result;
	}
	// remenber to commit the effor
	if(iptc_create_chain(chain_name, handle))
	{
		result = iptc_commit(handle);
	}
	iptc_free(handle);
	return result;
}

/** delete the chain should use less */
int delete_chain(char *table_name, char *chain_name)
{
	struct iptc_handle *handle = get_handle(table_name);
	int result = FAILED;
	if(!handle || !chain_name)
	{
		return result;
	}
	if(iptc_delete_chain(chain_name, handle))
	{
		result = iptc_commit(handle);
	}
	iptc_free(handle);
	return result;
}

/**
 * add a rule to the chain 
 * FIXME: there are many tyies of the command
 */
int add_rule(char *table_name, char *chain_name,
		char *inface, int proto,
		char *src_ip, int src_port,
		char *dst_ip, int dst_port,
		char *tar_action, h_flag flag)
{
	struct iptc_handle *handle = NULL;
	struct ipt_entry *entry = NULL;
	struct ipt_entry_target *pt = NULL;
	struct ipt_entry_match *pm = NULL;
	// sizeof(struct ipt_tcp) > sizeof(ipt_upd)
	// and so the tcp contain what upd has, 
	// so used the struct tcp is enough
	struct ipt_tcp *ptcp = NULL;
	size_t target_size;
	size_t match_size;
	size_t size;
	int i;
	int result = FAILED;

	handle = get_handle(table_name);
	if(!handle || !chain_name || !src_ip 
			|| !dst_ip || !tar_action)
	{
		printf(">>> add_rule argument is NULL or invaild\n");
		return result;
	}
	// must be align the the kernel struct size
	// or it will throw 'invalid argument' error
	match_size = XT_ALIGN(sizeof(struct ipt_entry_match))
		+ XT_ALIGN(sizeof(struct ipt_tcp));
	target_size = XT_ALIGN(sizeof(struct ipt_entry_target))
		+ XT_ALIGN(sizeof(int));
	size = XT_ALIGN(sizeof(*entry)) + match_size 
		+ target_size;
	// other alloc also ok
	entry = calloc(1, size);
	entry->target_offset = sizeof(*entry) + match_size;
	entry->next_offset = size;
	pm = (struct ipt_entry_match*) entry->elems;
	pm->u.user.match_size = match_size;
	pt = (struct ipt_entry_target*)(entry->elems + match_size);
	pt->u.user.target_size = target_size;
	ptcp = (struct ipt_tcp*) pm->data;
	if(inface)
	{
		strcpy(entry->ip.iniface, inface);
		for(i = 0; i < strlen(inface) + 1; ++i)
		{
			entry->ip.iniface_mask[i] = 0xff;
		}
	}
	struct protoent *p = getprotobynumber(proto);
	if(p != NULL)
	{
		entry->ip.proto = proto;
		strcpy(pm->u.user.name, p->p_name);
	}
	else 
	{
		// default is TCP
		entry->ip.proto = IPPROTO_TCP;
		strcpy(pm->u.user.name, "tcp");
	}


	entry->ip.src.s_addr = inet_addr(src_ip);
	// if didn't know the mask, set it to -1
	entry->ip.smsk.s_addr = -1;
	if(src_port >= 0 && src_port <= 0xffff)
	{
		ptcp->spts[0] = ptcp->spts[1] = src_port;
	} 
	else 
	{
		ptcp->spts[0] = 0;
		ptcp->spts[1] = 0xffff;
	}
	entry->ip.dst.s_addr = inet_addr(dst_ip);
	entry->ip.smsk.s_addr = -1;
	if(dst_port >= 0 && dst_port <= 0xffff)
	{
		ptcp->dpts[0] = ptcp->dpts[1] = dst_port;
	}
	else 
	{
		ptcp->dpts[0] = 0;
		ptcp->dpts[1] = 0xffff;
	}

	if(!strcmp(tar_action, ACTION_DROP) || !strcmp(tar_action, ACTION_REJECT)
			|| !strcmp(tar_action, ACTION_ACCEPT)) {
		strcpy(pt->u.user.name, tar_action);
	} 
	else 
	{
		// default is accept
		strcpy(pt->u.user.name, ACTION_ACCEPT);
	}

	if(flag == F_HEAD)
	{
		if(iptc_insert_entry(chain_name, entry, 0, handle))
		{
			result = iptc_commit(handle);
		} 
		else 
		{
			result = FAILED;
		}
	}
	else if(flag == F_NO_HEAD)
	{
		if(iptc_append_entry(chain_name, entry, handle))
		{
			result = iptc_commit(handle);
		}
		else 
		{
			result = FAILED;
		}
	}

	iptc_free(handle);
	free(entry);
	return result;
}

int add_rule2(char *table_name, char *chain_name,
		char *inface, int proto, char *src_ip, 
		char *dst_ip, char *tar_action,
		h_flag flag)
{
	int result = FAILED, i = 0;
	size_t target_size;
	size_t size;
	struct iptc_handle *handle;
	struct ipt_entry *entry;
	struct ipt_entry_target *pt;

	handle = get_handle(table_name);
	if(!handle || !chain_name)
	{
		return result;
	}

	target_size = XT_ALIGN(sizeof(struct ipt_entry_target))
		+ XT_ALIGN(sizeof(int));
	size = XT_ALIGN(sizeof(struct ipt_entry))
		+ target_size;

	entry = calloc(1, size);
	entry->target_offset = sizeof(struct ipt_entry);
	entry->next_offset = size;
	if(src_ip)
	{
		entry->ip.src.s_addr = inet_addr(src_ip? src_ip : DEFAULT_IP);
		entry->ip.smsk.s_addr = -1;
	}
	if(dst_ip)
	{
		entry->ip.dst.s_addr = inet_addr(dst_ip? dst_ip : DEFAULT_IP);
		entry->ip.dmsk.s_addr = -1;
	}
	if(inface)
	{
		strcpy(entry->ip.iniface, inface);
		for(i = 0; i < strlen(inface) + 1; ++i)
		{
			entry->ip.iniface_mask[i] = 0xff;
		}
	}
	entry->ip.proto = proto;

	pt = (struct ipt_entry_target*) entry->elems;
	pt->u.user.target_size = target_size;
	if(tar_action)
	{
		strcpy(pt->u.user.name, tar_action);
	}
	else 
	{
		strcpy(pt->u.user.name, ACTION_ACCEPT);
	}

	if(flag == F_HEAD)
	{
		if(iptc_insert_entry(chain_name, entry, 0, handle))
		{
			result = iptc_commit(handle);
		} 
		else 
		{
			result = FAILED;
		}
	}
	else if(flag == F_NO_HEAD)
	{
		if(iptc_append_entry(chain_name, entry, handle))
		{
			result = iptc_commit(handle);
		}
		else 
		{
			result = FAILED;
		}
	}

	iptc_free(handle);
	free(entry);
	return result;
}

/** 
 * add nat rule, something different
 */
int add_nat_rule(char *chain_name, char *inface,
		int proto, char *src_ip, int src_port,
		char *dst_ip, int dst_port, 
		char *nat_min_ip, int nat_min_port,
		char *nat_max_ip, int nat_max_port,
		char *tar_action, h_flag flag)
{
	struct iptc_handle *handle = NULL;
	struct ipt_entry *entry = NULL;
	struct ipt_entry_target *pt = NULL;
	// the nat parames of the target
	struct nf_nat_multi_range_compat *mr;
	struct ipt_entry_match *pm = NULL;
	struct ipt_tcp *ptcp = NULL;
	size_t target_size;
	size_t match_size;
	size_t size;
	int i;
	int result = FAILED;

	// the table must be 'nat'
	handle = get_handle("nat");
	if(!handle || !chain_name)
	{
		printf(">>> add_rule argument is NULL or invaild\n");
		return result;
	}
	// must be align the the kernel struct size
	// or it will throw 'invalid argument' error
	match_size = XT_ALIGN(sizeof(struct ipt_entry_match))
		+ XT_ALIGN(sizeof(struct ipt_tcp));
	target_size = XT_ALIGN(sizeof(struct ipt_entry_target))
		+ XT_ALIGN(sizeof(struct nf_nat_multi_range_compat));
	size = XT_ALIGN(sizeof(*entry)) + match_size 
		+ target_size;
	// other alloc also ok
	entry = calloc(1, size);
	entry->target_offset = sizeof(*entry) + match_size;
	entry->next_offset = size;
	pm = (struct ipt_entry_match*) entry->elems;
	pm->u.user.match_size = match_size;
	pt = (struct ipt_entry_target*)(entry->elems + match_size);
	pt->u.user.target_size = target_size;
	ptcp = (struct ipt_tcp*) pm->data;
	if(inface)
	{
		strcpy(entry->ip.iniface, inface);
		for(i = 0; i < strlen(inface) + 1; ++i)
		{
			entry->ip.iniface_mask[i] = 0xff;
		}
	}
	struct protoent *p = getprotobynumber(proto);
	if(p != NULL)
	{
		entry->ip.proto = proto;
		strcpy(pm->u.user.name, p->p_name);
	}
	else 
	{
		// default is TCP
		entry->ip.proto = IPPROTO_TCP;
		strcpy(pm->u.user.name, "tcp");
	}


	entry->ip.src.s_addr = inet_addr(src_ip? src_ip : DEFAULT_IP);
	// if didn't know the mask, set it to -1
	entry->ip.smsk.s_addr = -1;
	if(src_port >= 0 && src_port <= 0xffff)
	{
		ptcp->spts[0] = ptcp->spts[1] = src_port;
	} 
	else 
	{
		ptcp->spts[0] = 0;
		ptcp->spts[1] = 0xffff;
	}
	entry->ip.dst.s_addr = inet_addr(dst_ip? dst_ip : DEFAULT_IP);
	entry->ip.smsk.s_addr = -1;
	if(dst_port >= 0 && dst_port <= 0xffff)
	{
		ptcp->dpts[0] = ptcp->dpts[1] = dst_port;
	}
	else 
	{
		ptcp->dpts[0] = 0;
		ptcp->dpts[1] = 0xffff;
	}

	if(!strcmp(tar_action, ACTION_SNAT) 
			|| !strcmp(tar_action, ACTION_DNAT)) {
		strcpy(pt->u.user.name, tar_action);
	}
	else 
	{
		// default is DNAT
		strcpy(pt->u.user.name, ACTION_DNAT);
	}

	// the target nat rule
	mr = (struct nf_nat_multi_range_compat*) pt->data;
	mr->rangesize = 1;
	mr->range[0].flags = IP_NAT_RANGE_MAP_IPS;
	mr->range[0].min_ip = inet_addr(nat_min_ip? nat_min_ip : DEFAULT_IP);
	mr->range[0].max_ip = inet_addr(nat_max_ip? nat_max_ip : DEFAULT_IP);
	mr->range[0].min.tcp.port = 
		(nat_min_port > 0 && nat_min_port < 0xffff? nat_min_port : 0);
	mr->range[0].max.tcp.port = 
		(nat_max_port > 0 && nat_max_port < 0xffff? nat_max_port : 0xffff);

	if(flag == F_HEAD)
	{
		if(iptc_insert_entry(chain_name, entry, 0, handle))
		{
			result = iptc_commit(handle);
		} 
		else 
		{
			result = FAILED;
		}
	}
	else if(flag == F_NO_HEAD)
	{
		if(iptc_append_entry(chain_name, entry, handle))
		{
			result = iptc_commit(handle);
		}
		else 
		{
			result = FAILED;
		}
	}

	iptc_free(handle);
	free(entry);
	return result;
}


/** delete a rule from chain */
int delete_rule_at_index(char *table_name,
		char *chain_name, int index)
{
	struct iptc_handle *handle = get_handle(table_name);
	int result = FAILED;
	if(!handle || !chain_name)
	{
		return result;
	}
	if(iptc_delete_num_entry(chain_name, index, handle))
	{
		result = iptc_commit(handle);
	}
	iptc_free(handle);
	return result;
}

/** flush all link's rules shoud use less*/
int flush_chain(char *table_name, char *chain_name)
{
	struct iptc_handle *handle = get_handle(table_name);
	int result = FAILED;
	if(!handle || !chain_name)
	{
		return result;
	}
	if(iptc_flush_entries(chain_name, handle))
	{
		result = iptc_commit(handle);
	}
	iptc_free(handle);
	return result;
}

// get all ip datas
ip_link_t* get_ip_all()
{
	ip_link_t *head = NULL;
	ip_link_t *link1 = get_ip_by_table("filter");
	ip_link_t *link2 = get_ip_by_table("nat");
	ip_link_t *link3 = get_ip_by_table("mangle");
	head = link1;
	while(link1 && link1->next) 
	{
		link1 = link1->next;
	}
	if(link1) 
	{
		link1->next = link2;
	}
	while(link2 && link2->next) 
	{
		link2 = link2->next;
	}
	if(link2) 
	{
		link2->next = link3;
	}
	return head;
}

// get all chain ip in table
ip_link_t* get_ip_by_table(char *table_name)
{
	ip_link_t *head = NULL;
	ip_link_t *t = NULL;
	ip_link_t *link = NULL;
	const char *chain_name;
	struct iptc_handle *handle;
	handle = get_handle(table_name);
	if(!handle)
	{
		return head;
	}

	for(chain_name = iptc_first_chain(handle); chain_name;
			chain_name = iptc_next_chain(handle))
	{
		link = get_ip_by_table_chain(table_name, chain_name);
		if(!head)
		{
			head = t = link;
			continue;
		}
		while(t->next)
		{
			t = t->next;
		}
		t->next = link;
	}

	return head;
}

ip_link_t* get_ip_by_table_chain(const char *table_name, 
		const char *chain_name)
{
	ip_link_t *head = NULL;
	ip_link_t *t, *l = NULL;
	int index = 0;
	struct iptc_handle *handle;
	const struct ipt_entry *entry;
	struct ipt_entry_target *target;
	struct ipt_tcp *ptcp;
	struct nf_nat_multi_range_compat* mr;

	struct in_addr addr;

	handle = get_handle(table_name);
	if(!handle || !chain_name)
	{
		return head;
	}

	for(entry = iptc_first_rule(chain_name, handle); 
			entry; entry = iptc_next_rule(entry, handle))
	{
		// to save the index postion in the chain
		t = (ip_link_t *)malloc(sizeof(ip_link_t));
		bzero(t, sizeof(ip_link_t));
		t->ip.index = index ++;
		strcpy(t->ip.src_ip, inet_ntoa(entry->ip.src));
		strcpy(t->ip.dst_ip, inet_ntoa(entry->ip.dst));
		target = (void*)entry + entry->target_offset;
		if((void*)target == (void*)entry->elems)
		{
			strcpy(t->ip.src_port, "all");
			strcpy(t->ip.dst_port, "all");
		}
		else 
		{
			char *format = "";
			ptcp = (struct ipt_tcp*)((struct ipt_entry_match*)entry->elems)->data;
			if(ptcp->spts[0] == ptcp->spts[1]) format = "%d";
			else format = "%d-%d";
			if(ptcp->spts[0] == 0 && ptcp->spts[1] == 0xffff) 
			{
				strcpy(t->ip.src_port, "all");
			}
			else 
			{
				sprintf(t->ip.src_port, format, ptcp->spts[0], ptcp->spts[1]);
			}
			if(ptcp->dpts[0] == ptcp->dpts[1]) format = "%d";
			else format = "%d-%d";
			if(ptcp->dpts[0] == 0 && ptcp->dpts[1] == 0xffff)
			{
				strcpy(t->ip.dst_port, "all");
			}
			else 
			{
				sprintf(t->ip.dst_port, format, ptcp->dpts[0], ptcp->dpts[1]);
			}
		}

		if(target->u.user.target_size >= sizeof(struct ipt_entry_target) 
				+ sizeof(struct nf_nat_multi_range_compat))
		{
			mr = (struct nf_nat_multi_range_compat*) target->data;
			bzero(&addr, sizeof(struct in_addr));
			addr.s_addr  = (int) mr->range[0].min_ip;
			strcpy(t->ip.nat_minip, inet_ntoa(addr));
			addr.s_addr = (int) mr->range[0].max_ip;
			strcpy(t->ip.nat_maxip, inet_ntoa(addr));
		}

		t->ip.proto = entry->ip.proto;
		strcpy(t->ip.chain, chain_name);
		strcpy(t->ip.table, table_name);
		strcpy(t->ip.action, iptc_get_target(entry, handle));
		t->next = NULL;
		if(!head)
		{
			head = l = t;
			continue;
		}
		l->next = t;
		l = l->next;
	}

	return head;
}

// free the malloc memory
void free_ip_link(ip_link_t *head)
{
	ip_link_t *t = head;
	if(!head)
	{
		return;
	}
	while(t)
	{
		head = head->next;
		free(t);
		t = head;
	}
}

/************************************************/
/****************** netcap.h ********************/
/************************************************/

extern pcap_t *descr;

int cap_init(const char *device)
{
	if(!device)
	{
		return 0;
	}
	descr = pcap_open_live(device, 0xffff, 1, 0, NULL);
	return descr? 1 : 0;
}

void get_netcap(netcap_t *info)
{
	struct ip *iphdr = NULL;
	struct pcap_pkthdr pkthdr;
	struct protoent *proto = NULL;
	const char *packet = NULL;
	packet = pcap_next(descr, &pkthdr);
	iphdr = (struct ip *) (packet + 14);
	proto = getprotobynumber(iphdr->ip_p);
	if(proto != NULL)
	{
		strcpy(info->proto, proto->p_name);
	}
	else 
	{
		strcpy(info->proto, "other");
	}
	strcpy(info->src_ip, inet_ntoa(iphdr->ip_src));
	strcpy(info->dst_ip, inet_ntoa(iphdr->ip_dst));
	info->len = pkthdr.len;
}
void cap_close()
{
	if(!descr)
	{
		return;
	}
	pcap_close(descr);
	descr = NULL;
}

/* =================== test ================== */

/* 
   int main(int argc, char **argv)
   {
   if(!add_chain("filter", "hello"))
   {
   perror("filter");
   }
// delete_chain("filter", "hello");
// delete_rule_at_index("filter", "INPUT", 5);
add_rule("filter", "FORWARD", NULL,
IPPROTO_UDP, "172.168.166.166", -1, 
"172.168,90.98", 80,
"ACCEPT", F_HEAD);
add_rule2("filter", "FORWARD", NULL, 
IPPROTO_ICMP, "195.8.8.2", NULL, "ACCEPT", F_HEAD);
// add_rule2("filter", "INPUT", NULL, 
//     0, "195.8.8.2", "189.98.9.90", "ACCEPT", F_HEAD);
// ip_link_t *head = get_ip_by_table_chain("filter", "INPUT");
ip_link_t *head = get_ip_all();
ip_link_t *t = head;
while(t)
{
printf("table: %s --->", t->ip.table);
printf("%s src=%s:%s ", t->ip.chain, t->ip.src_ip, t->ip.src_port);
printf("dst=%s:%s action: %s index: %d\n", t->ip.dst_ip,
t->ip.dst_port, t->ip.action, t->ip.index);
t = t->next;
}
free_ip_link(head);
// fflush(stdout);
// printf("\n");
return 0;
}*/
/*
   int main(int argc, char **argv)
   {

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
   add_nat_rule("PREROUTING", NULL, IPPROTO_TCP, "199.199.199.199", 
   97, NULL, -1, "192.199.128.250", -1, "192.199.128.190", -1, "DNAT", F_HEAD);
   perror(">>>> msg");
   return 0;
   }*/
