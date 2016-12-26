#include "ipTransmitTunnel.h"

MODULE_LICENSE("GPL");

MODULE_DESCRIPTION("ip transmit tunnel");


static char *proxyIpStr = NULL;
static unsigned proxyIp=0;

module_param(proxyIpStr, charp, 0);

MODULE_PARM_DESC(proxyIpStr,"RCM Address to send tunnel traffic to");

//the structure used to register the function

struct nf_hook_ops hook_PRE, hook_IN, hook_POST_ROUTING, hook_OUT;
struct net_device *gUsb0Iface=NULL, *gWifiIface=NULL;
unsigned int wifiIp=0, usb0Ip=0;


char * ipString(unsigned int ip, char *str)
{
    unsigned char * walker;
    ip = ntohl(ip);
    walker = (char *)&ip;
    sprintf(str, "%u.%u.%u.%u", walker[3], walker[2], walker[1], walker[0]);

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
    struct net *lteNet;
    struct iphdr *innerIpHdr=(struct iphdr *)skb_network_header(skb);
    struct iphdr *outerIpHdr=NULL;
    //struct ethhdr *neth_hdr;
    //struct udphdr *udp_header;

    unsigned int src_ip = (unsigned int)innerIpHdr->saddr;
    //unsigned int dest_ip = (unsigned int)innerIpHdr->daddr;
    unsigned int innerPktLen = 0;

    //char * payload;
    //int ret;
    //unsigned char *d;

    /* TO DO: If LTE interface goes down, this code will crash the device */
    struct rtable *rt;
    struct flowi4 fl = {};

    if(src_ip == wifiIp && 0!=usb0Ip && 0!=proxyIp)
    {
        innerPktLen = ntohs(innerIpHdr->tot_len);

        if(innerIpHdr->protocol == 17)
        {
            //udp_header = (struct udphdr *) ((void *)innerIpHdr + (innerIpHdr->ihl*4));
            printUDP("POST_ROUTING", skb, innerIpHdr);
        }
        else
            printIP("POST_ROUTING", skb, innerIpHdr);


        if( skb_headroom(skb) < sizeof(struct iphdr) )
        {
            printk(KERN_INFO "POST_ROUTING skb headroom not enough. expanding");
            if( 0 != pskb_expand_head( skb, (sizeof(struct iphdr)) - skb_headroom(skb), 0, GFP_ATOMIC) )
            {
                printk(KERN_INFO "POST_ROUTING pskb_expand_head failed");
                kfree_skb(skb);
                return NF_STOLEN;
            }
        }

        outerIpHdr = (struct iphdr *) skb_push(skb, sizeof(struct iphdr));
        outerIpHdr->version = 4;
        outerIpHdr->ihl = 5;
        outerIpHdr->tos = innerIpHdr->tos;
        outerIpHdr->tot_len = htons(sizeof(struct iphdr) + innerPktLen);
        outerIpHdr->id = 0; //innerIpHdr->id; /* TO DO: Is it right to copy it as is? */
        outerIpHdr->frag_off = 0; //innerIpHdr->frag_off; /* TO DO: Is it right to copy it as is? */
        outerIpHdr->ttl = 60; /* TO DO: inner ttl has to be decremented and outer ttl has to be set appropriately */
        outerIpHdr->protocol = 4;
        outerIpHdr->check = 0; /* TO DO */
        outerIpHdr->saddr = usb0Ip; //in_aton("10.224.205.134");
        outerIpHdr->daddr = proxyIp; //in_aton("10.224.205.134");
        outerIpHdr->check = ip_fast_csum( (uint16_t *)outerIpHdr, (outerIpHdr->ihl) );

        skb_reset_network_header(skb);

        fl.daddr = outerIpHdr->daddr;
        fl.saddr = outerIpHdr->saddr;
        fl.flowi4_oif = gUsb0Iface->ifindex;


        lteNet = dev_net(gUsb0Iface);
        rt = ip_route_output_key(lteNet, &fl);
        //rt = ip_route_output_key(&init_net, &fl);
        skb_dst_drop(skb);
        skb_dst_set(skb, &rt->dst);
        skb->dev = skb_dst(skb)->dev;

        printIP("POST_ROUTING", skb, outerIpHdr);
#if 0
        skb->dev = gUsb0Iface;
        skb->ip_summed = CHECKSUM_NONE;
        skb->pkt_type = PACKET_OTHERHOST;

        if( skb_headroom(skb) < sizeof(struct ethhdr) )
        {
            if( 0 != pskb_expand_head( skb, (sizeof(struct ethhdr)) - skb_headroom(skb), 0, GFP_ATOMIC) )
            {
                printk(KERN_INFO "POST_ROUTING pskb_expand_head failed");
                kfree_skb(skb);
                return NF_STOLEN;
            }
        }
        neth_hdr = (struct ethhdr *)skb_push(skb, ETH_HLEN);
        if(neth_hdr != NULL)
        {
            memcpy(neth_hdr->h_source, skb->dev->dev_addr, ETH_ALEN);
            d = neth_hdr->h_dest;
            //00:00:0c:07:ac:cd
            d[0] = 0x00; d[1]=0x00; d[2]=0x0c; d[3]=0x07; d[4]=0xac; d[5]=0xcd;
            neth_hdr->h_proto = __constant_htons(ETH_P_IP);
        }
        else
        {
            printk(KERN_INFO "POST_ROUTING neth_hdr allocation failed\n");
        }

        ret = dev_queue_xmit(skb);
        printk(KERN_INFO "POST_ROUTING dev_queue_xmit returned %d\n", ret);
        return NF_STOLEN;
#endif
    }
    else
        printIP("POST_ROUTING not tunnelling ", skb, innerIpHdr);

    printk(KERN_INFO "---------------------------------------\n");

    return NF_ACCEPT;
}


/*
 * in_cksum --  borrowed from the net -- https://ubuntuforums.org/showthread.php?t=1955101
 * Checksum routine for Internet Protocol
 * family headers (C Version)
 */
unsigned short in_cksum(unsigned short *addr, int len)
{
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;
    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    /* mop up an odd byte, if necessary */
    if (nleft == 1)
    {
        *(u_char *) (&answer) = *(u_char *) w;
        sum += answer;
    }
    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum += (sum >> 16);             /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return (answer);
}


//the hook function itself: registered for filtering incoming packets

unsigned int hook_func_pre_routing
(
 const struct nf_hook_ops *ops,
 //unsigned int hookno,
 struct sk_buff *skb,
 const struct net_device *in,
 const struct net_device *out,
 int (*okfn)(struct sk_buff *)
 )
{
    struct rtable *rt;
    struct flowi4 fl = {};
    //struct net *net;
    struct iphdr *outerIpHdr = (struct iphdr *)skb_network_header(skb);
    struct iphdr *innerIpHdr;

    unsigned int src_ip = (unsigned int)outerIpHdr->saddr;
    unsigned int dest_ip = (unsigned int)outerIpHdr->daddr;
    unsigned int src_port = 0;
    unsigned int dest_port = 0;
    unsigned int tot_len = 0;
    struct udphdr *udp_header;
    struct tcphdr *tcp_header;
    struct icmphdr *icmp_header;

    char srcIpStr[20], dstIpStr[20];
    char refDst[20];

    switch(outerIpHdr->protocol)
    {
        case 17:
            printUDP("PREROUTING", skb, outerIpHdr);
            break;
        case 6:
            {
                printTCP("PREROUTING", skb, outerIpHdr);
            }
            break;
        case 1:
            printIP("PREROUTING", skb, outerIpHdr);
            break;
        case 4:
            {
                printk(KERN_INFO "PREROUTING packet info: iFace:%s, sIp: %s, dIp: %s, proto: %u; tot_len=%d, headroom=%d, refdst=%s\n", 
                        skb->dev->name, ipString(src_ip, srcIpStr), ipString(dest_ip, dstIpStr), outerIpHdr->protocol, 
                        ntohs(outerIpHdr->tot_len), skb_headroom(skb), ipString(skb->_skb_refdst, refDst) );

                skb_pull(skb, outerIpHdr->ihl*4);
                skb_reset_network_header(skb);

                innerIpHdr = (struct iphdr *)skb_network_header(skb);

                src_ip      = (unsigned int)innerIpHdr->saddr;
                dest_ip     = (unsigned int)innerIpHdr->daddr;
                fl.daddr    = dest_ip;
                fl.saddr    = src_ip;

                rt = ip_route_output_key(&init_net, &fl);
                skb_dst_drop(skb);
                skb_dst_set(skb, &rt->dst);
                skb->dev = skb_dst(skb)->dev;

                tot_len = ntohs(innerIpHdr->tot_len);
                if(pskb_trim_rcsum(skb, tot_len))
                {
                    printk(KERN_INFO "pskb_trim_rcsum returned error");
                    return NF_STOLEN;
                }

                skb->transport_header = skb->network_header + innerIpHdr->ihl*4;

                if(innerIpHdr->protocol == 17)
                {
                    udp_header = (struct udphdr *) ((void *)innerIpHdr + (innerIpHdr->ihl*4));
                    if( unlikely(skb_linearize(skb) != 0))
                    {
                        return NF_STOLEN;
                    }

                    udp_header->check = 0;
                    udp_header->check = csum_tcpudp_magic(innerIpHdr->saddr, innerIpHdr->daddr, ntohs(udp_header->len), IPPROTO_UDP,
                            csum_partial( (unsigned char *)udp_header, ntohs(udp_header->len), 0));

                    printUDP("PREROUTING", skb, innerIpHdr);
                }
                else if( innerIpHdr->protocol == 6)
                {
                    tcp_header = (struct tcphdr *) ((void *)innerIpHdr + (innerIpHdr->ihl*4));
                    if( unlikely(skb_linearize(skb) != 0))
                    {
                        return NF_STOLEN;
                    }

                    tcp_header->check = 0;
                    tcp_header->check = csum_tcpudp_magic(innerIpHdr->saddr, innerIpHdr->daddr, tot_len-innerIpHdr->ihl*4, IPPROTO_TCP,
                            csum_partial( (unsigned char *)tcp_header, tot_len-innerIpHdr->ihl*4, 0));
                    printk(KERN_INFO "PREROUTING after:iFace:%s, sIp:%s, sPort:%u; dIp:%s, dPort:%u; proto%u; tot_len=%d, headroom=%d, refdst=%s, tcpcsum=%d\n", 
                            skb->dev->name, ipString(src_ip, srcIpStr), src_port, ipString(dest_ip, dstIpStr), dest_port, innerIpHdr->protocol, ntohs(innerIpHdr->tot_len), skb_headroom(skb), ipString(skb->_skb_refdst, refDst), tcp_header->check);

                }
                else if( innerIpHdr->protocol == 1)
                {
                    icmp_header = (struct icmphdr *) ((void *)innerIpHdr + (innerIpHdr->ihl*4));
                    if( unlikely(skb_linearize(skb) != 0))
                    {
                        return NF_STOLEN;
                    }

                    icmp_header->checksum = 0;
                    icmp_header->checksum = in_cksum((ushort *)icmp_header, tot_len - innerIpHdr->ihl*4);
                    printk(KERN_INFO "PREROUTING after:iFace:%s, sIp:%s, dIp:%s, proto%u; tot_len=%d, headroom=%d, refdst=%s, checksumm=%d\n", 
                            skb->dev->name, ipString(src_ip, srcIpStr), ipString(dest_ip, dstIpStr), innerIpHdr->protocol, ntohs(innerIpHdr->tot_len), skb_headroom(skb), ipString(skb->_skb_refdst, refDst), icmp_header->checksum);

                }
                else
                    printk(KERN_INFO "PREROUTING after rtable step: iFace:%s, sIp: %s, dIp: %s, proto: %u; tot_len=%d, headroom=%d, refdst=%s\n", 
                            skb->dev->name, ipString(src_ip, srcIpStr), ipString(dest_ip, dstIpStr), innerIpHdr->protocol, 
                            ntohs(innerIpHdr->tot_len), skb_headroom(skb), ipString(skb->_skb_refdst, refDst));
            }
            break;
    }

    printk(KERN_INFO "---------------------------------------\n");

    return NF_ACCEPT;
}

unsigned int hook_func_in
(
 const struct nf_hook_ops *ops,
 //unsigned int hookno,
 struct sk_buff *skb,
 const struct net_device *in,
 const struct net_device *out,
 int (*okfn)(struct sk_buff *)
 )
{
    struct iphdr *ipHdr = (struct iphdr *)skb_network_header(skb);

    switch(ipHdr->protocol)
    {
        case 17:
            printUDP("IN", skb, ipHdr);
            break;
        case 6:
            printTCP("IN", skb, ipHdr);
            break;
        case 1:
        case 4:
            printIP("IN", skb, ipHdr);
            break;
    }

    printk(KERN_INFO "---------------------------------------\n");

    return NF_ACCEPT;

}


unsigned int hook_func_local_out(
        const struct nf_hook_ops *ops, 
        //unsigned int hookno,
        struct sk_buff *skb,
        const struct net_device *in, 
        const struct net_device *out,
        int (*okfn)(struct sk_buff *)
        )
{

    struct iphdr *ipHdr = (struct iphdr *)skb_network_header(skb);

    switch(ipHdr->protocol)
    {
        case 17:
            {
                printUDP("LOCAL_OUT", skb, ipHdr);
            }
            break;
        case 6:
            printTCP("LOCAL_OUT", skb, ipHdr);
            break;
        case 1:
        case 4:
            printIP("LOCAL_OUT", skb, ipHdr);
            break;
    }

    printk(KERN_INFO "---------------------------------------\n");

    return NF_ACCEPT;
}

/* Initialization routine */

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

    /* Fill in the hook structure for pre-routing incoming packet hook*/
    hook_PRE.hook       = hook_func_pre_routing;
    hook_PRE.hooknum    = NF_INET_PRE_ROUTING;
    hook_PRE.pf         = PF_INET;
    hook_PRE.priority   = NF_IP_PRI_FIRST;
    //nf_register_hook(&hook_PRE);         // Register the hook

    /* Fill in the hook structure for incoming packet hook*/
    hook_IN.hook        = hook_func_in;
    hook_IN.hooknum     = NF_INET_LOCAL_IN;
    hook_IN.pf          = PF_INET;
    hook_IN.priority    = NF_IP_PRI_FIRST;
    //nf_register_hook(&hook_IN);         // Register the hook


    /* Fill in the hook structure for outgoing packet hook*/

    hook_POST_ROUTING.hook       = hook_func_post_routing;
    hook_POST_ROUTING.hooknum    = NF_INET_POST_ROUTING;
    hook_POST_ROUTING.pf         = PF_INET;
    hook_POST_ROUTING.priority   = NF_IP_PRI_FIRST;
    nf_register_hook(&hook_POST_ROUTING);    // Register the hook

    /* Fill in the hook structure for outgoing packet hook*/

    hook_OUT.hook      = hook_func_local_out;
    hook_OUT.hooknum   = NF_INET_LOCAL_OUT;
    hook_OUT.pf        = PF_INET;
    hook_OUT.priority  = NF_IP_PRI_FIRST;
    //nf_register_hook(&hook_OUT );    // Register the hook

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

    if(NULL != gUsb0Iface)
        printk(KERN_INFO "gUsb0Iface= [%s], ip=%u\n", gUsb0Iface->name, usb0Ip);

    if(NULL != gWifiIface)
        printk(KERN_INFO "gWifiIface= [%s], ip=%u\n", gWifiIface->name, wifiIp);

    return 0;
}

/* Cleanup routine */

static void __exit cleanup_ipip_module(void)
{
    nf_unregister_hook(&hook_POST_ROUTING);

    printk(KERN_INFO "ipip-tunnel module unloaded.\n");
}


module_init(init_ipip_module);

module_exit(cleanup_ipip_module);
