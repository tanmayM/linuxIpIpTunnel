#include "ipipTransmit_Tunnel.h"

MODULE_LICENSE("GPL");

MODULE_DESCRIPTION("ipip tunnel");

static char *proxyIpStr = NULL;
static unsigned proxyIp=0;

module_param(proxyIpStr, charp, 0);

MODULE_PARM_DESC(proxyIpStr,"Proxy server IP");

//the structure used to register the function

struct nf_hook_ops hook_POSTROUTING;
struct net_device *gUsb0Iface=NULL, *gWifiIface=NULL;
unsigned int wifiIp=0, usb0Ip=0;

char * ipString(unsigned int ip, char *str)
{
    unsigned char * xx;
    ip = ntohl(ip);
    xx = (char *)&ip;
    sprintf(str, "%u.%u.%u.%u", xx[3], xx[2], xx[1], xx[0]);

    return str;
}

unsigned int hook_func_post_routing
(
 const struct nf_hook_ops *ops,
 //unsigned int hookno,
 struct sk_buff *skb,
 const struct net_device *in,
 const struct net_device *out,
 int (*okfn)(struct sk_buff *)
 )
{
    struct iphdr *innerIpHdr=(struct iphdr *)skb_network_header(skb);
    struct iphdr *outerIpHdr=NULL;
    struct ethhdr *neth_hdr;

    unsigned int src_ip = (unsigned int)innerIpHdr->saddr;
    unsigned int innerPktLen = 0;
    int ret=0;

    if( 1==netif_running(gUsb0Iface) && src_ip == wifiIp && 0!=usb0Ip && 0!=proxyIp)
    {
        innerPktLen = ntohs(innerIpHdr->tot_len);

        printIP("POSTROUTING", skb, innerIpHdr);

        if( skb_headroom(skb) < sizeof(struct iphdr) )
        {
            printk(KERN_INFO "POSTROUTING skb headroom not enough. expanding");
            if( 0 != pskb_expand_head( skb, (sizeof(struct iphdr)) - skb_headroom(skb), 0, GFP_ATOMIC) )
            {
                printk(KERN_INFO "POSTROUTING pskb_expand_head failed");
                kfree_skb(skb);
                return NF_STOLEN;
            }
        }

        outerIpHdr = (struct iphdr *) skb_push(skb, sizeof(struct iphdr));
        outerIpHdr->version = 4;
        outerIpHdr->ihl = 5;
        outerIpHdr->tos = innerIpHdr->tos;
        outerIpHdr->tot_len = htons(sizeof(struct iphdr) + innerPktLen);
        outerIpHdr->id = 0;
        outerIpHdr->frag_off = innerIpHdr->frag_off;
        outerIpHdr->ttl = innerIpHdr->ttl;
        outerIpHdr->protocol = 4;
        outerIpHdr->saddr = usb0Ip;
        outerIpHdr->daddr = proxyIp;
        outerIpHdr->check = 0;
        outerIpHdr->check = ip_fast_csum( (uint16_t *)outerIpHdr, (outerIpHdr->ihl) );

        skb_reset_network_header(skb);

        skb->dev = gUsb0Iface;
        skb->ip_summed = CHECKSUM_NONE;
        skb->pkt_type = PACKET_OTHERHOST;

        if( skb_headroom(skb) < sizeof(struct ethhdr) )
        {
            if( 0 != pskb_expand_head( skb, (sizeof(struct ethhdr)) - skb_headroom(skb), 0, GFP_ATOMIC) )
            {
                printk(KERN_INFO "POSTROUTING pskb_expand_head failed");
                kfree_skb(skb);
                return NF_STOLEN;
            }
        }

        neth_hdr = (struct ethhdr *)skb_push(skb, ETH_HLEN);
        if(neth_hdr != NULL)
        {
            memcpy(neth_hdr->h_source, skb->dev->dev_addr, ETH_ALEN);
            neth_hdr->h_proto = __constant_htons(ETH_P_IP);
        }
        else
        {
            printk(KERN_INFO "POSTROUTING neth_hdr allocation failed\n");
        }

        printIP("POSTROUTING", skb, outerIpHdr);
        ret = dev_queue_xmit(skb);
        printk(KERN_INFO "POSTROUTING dev_queue_xmit returned %d\n", ret);
        return NF_STOLEN;
    }
    else
        printIP("POSTROUTING not tunnelling ", skb, innerIpHdr);

    printk(KERN_INFO "---------------------------------------\n");

    return NF_ACCEPT;
}


static int __init init_ipip_module(void)
{
    struct net_device *dev = NULL;
    struct in_device *in_dev = NULL;
    struct in_ifaddr *if_info = NULL;
    __u8 *addr = NULL;

    if(NULL != proxyIpStr)
    {
        proxyIp = in_aton(proxyIpStr);
        printk(KERN_INFO "initialize ipip-tunnel module, Received proxyIpStr=%s, proxyIp=%u\n", proxyIpStr, proxyIp);
    }
    else
        printk(KERN_INFO "initialize ipip-tunnel module, proxyIpStr=NULL\n");


    /* Fill in the hook structure for outgoing packet hook*/

    hook_POSTROUTING.hook       = hook_func_post_routing;
    hook_POSTROUTING.hooknum    = NF_INET_POST_ROUTING;
    hook_POSTROUTING.pf         = PF_INET;
    hook_POSTROUTING.priority   = NF_IP_PRI_FIRST;
    nf_register_hook(&hook_POSTROUTING);    // Register the hook

    dev = first_net_device(&init_net);
    while(dev)
    {
        /* TO DO: This code crashes the device if interface is not up */
        if(NULL != dev->name && NULL != dev->dev_addr)
        {
            if(0==netif_running(dev))
            {
                printk(KERN_INFO "found [%s], isUP=%d\n", dev->name, netif_running(dev) );
                dev = next_net_device(dev);
                continue;
            }

            printk(KERN_INFO "found [%s], isUP=%d, dev_addr=%pMF\n", dev->name, netif_running(dev), dev->dev_addr);
            if( !strncmp("usb0", dev->name, 4) )
            {
                gUsb0Iface = dev;

                in_dev = (struct in_device *)dev->ip_ptr;
                if(NULL == in_dev)
                    continue;
                if_info = in_dev->ifa_list;
                if(NULL == if_info)
                    continue; 
                addr = (char *) &if_info->ifa_local;
                usb0Ip = if_info->ifa_local;

                printk(KERN_INFO "ip:%u.%u.%u.%u\n", (__u32)addr[0], (__u32)addr[1], (__u32)addr[2], (__u32)addr[3]);
            }
            else if( !strncmp("wlan0", dev->name, 5) )
            {
                gWifiIface = dev;
                in_dev = (struct in_device *)dev->ip_ptr;
                if(NULL == in_dev)
                    continue;
                if_info = in_dev->ifa_list;
                if(NULL == if_info)
                    continue; 
                addr = (char *) &if_info->ifa_local;
                wifiIp = if_info->ifa_local;

                printk(KERN_INFO "ip:%u.%u.%u.%u\n", (__u32)addr[0], (__u32)addr[1], (__u32)addr[2], (__u32)addr[3]);
            }
        }
        dev = next_net_device(dev);
    }

    return 0;
}

static void __exit cleanup_ipip_module(void)
{
    nf_unregister_hook(&hook_POSTROUTING);

    printk(KERN_INFO "ipip-tunnel module unloaded.\n");
}


module_init(init_ipip_module);

module_exit(cleanup_ipip_module);
