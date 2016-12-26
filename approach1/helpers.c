#include "ipipTransmit_Tunnel.h"

void getTCPHeaders(struct sk_buff *skb, unsigned int * sPort, unsigned int *dPort)
{
    struct tcphdr *tcp_header;
    tcp_header = (struct tcphdr *)(skb_transport_header(skb));
    *sPort = (unsigned int)ntohs(tcp_header->source);
    *dPort = (unsigned int)ntohs(tcp_header->dest);
}

void getUDPHeaders(struct sk_buff *skb, unsigned int * sPort, unsigned int *dPort)
{
    struct udphdr *uHdr;
    uHdr = (struct udphdr *)(skb_transport_header(skb));
    *sPort = (unsigned int)ntohs(uHdr->source);
    *dPort = (unsigned int)ntohs(uHdr->dest);
}


void printIP(char *prefix, struct sk_buff *skb, struct iphdr *ipHdr)
{
    char srcIpStr[20], dstIpStr[20];
    printk(KERN_INFO "%s IP: iFace:%s, sIp: %s, dIp: %s, proto: %u; tot_len=%d\n", prefix,
            skb->dev->name, ipString(ipHdr->saddr, srcIpStr), ipString(ipHdr->daddr, dstIpStr), ipHdr->protocol, ntohs(ipHdr->tot_len)); 
}

void printUDP(char *prefix, struct sk_buff *skb, struct iphdr *ipHdr)
{
    unsigned int sIp = (unsigned int)ipHdr->saddr;
    unsigned int dIp = (unsigned int)ipHdr->daddr;
    unsigned int sPort = 0;//(unsigned int)ntohs(uHdr->source);
    unsigned int dPort = 0;//(unsigned int)ntohs(uHdr->dest);
    char srcIpStr[20], dstIpStr[20], refDst[20];
    struct udphdr *uHdr = (struct udphdr *)(skb_transport_header(skb));

    getUDPHeaders(skb, &sPort, &dPort);

    printk(KERN_INFO "%s:iFace:%s, sIp:%s, sPort:%u; dIp:%s, dPort:%u; proto%u; tot_len=%d, headroom=%d, refdst=%s, udpLen=%u, udpcsum=%d\n", 
            prefix, skb->dev->name, ipString(sIp, srcIpStr), sPort, ipString(dIp, dstIpStr), dPort, ipHdr->protocol, ntohs(ipHdr->tot_len),
            skb_headroom(skb), ipString(skb->_skb_refdst, refDst), ntohs(uHdr->len), uHdr->check);

}


void printTCP(char *prefix, struct sk_buff *skb, struct iphdr *ipHdr)
{
    unsigned int sIp = (unsigned int)ipHdr->saddr;
    unsigned int dIp = (unsigned int)ipHdr->daddr;
    unsigned int sPort;
    unsigned int dPort;
    char srcIpStr[20], dstIpStr[20];

    getTCPHeaders(skb, &sPort, &dPort);
    printk(KERN_INFO "%s TCP: iFace:%s, sIp: %s, sPort: %u; dIp: %s, dPort: %u; proto: %u; tot_len=%d\n", prefix,
            skb->dev->name, ipString(sIp, srcIpStr), sPort, ipString(dIp, dstIpStr), dPort, ipHdr->protocol, ntohs(ipHdr->tot_len));

}
