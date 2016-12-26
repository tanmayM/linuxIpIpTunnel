#ifndef _BOOST_IPIP_TUNNEL
#define  _BOOST_IPIP_TUNNEL

#include <linux/module.h>
//#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <net/route.h>
#include <net/arp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/icmp.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>

void getTCPHeaders(struct sk_buff *skb, unsigned int * sPort, unsigned int *dPort);


void getUDPHeaders(struct sk_buff *skb, unsigned int * sPort, unsigned int *dPort);

char * ipString(unsigned int ip, char *str);

void printUDP(char *prefix, struct sk_buff *skb, struct iphdr *ipHdr);

void printTCP(char *prefix, struct sk_buff *skb, struct iphdr *ipHdr);

void printIP(char *prefix, struct sk_buff *skb, struct iphdr *ipHdr);
#endif
