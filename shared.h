



#ifndef SHARED_H
#define SHARED_H

// +-----   Includes   -----+ //

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <pcap.h>

// +-----   Includes   -----+ //


//DHCP
#define DHCP_OPCODE            1
#define DHCP_FILE_LEN          128
#define DHCP_OPTION_LEN        308
#define CLIENT_HARDWARE_ADDR   16
#define MCOOKIE_LEN            4
#define DHCP_HTYPE             0x01
#define DHCP_HLEN              6
#define DHCP_HOP               0x00
#define DHCP_SEC               0x00
#define DHCP_BCAST             0x8000
#define SNAME                  64
#define DCOOKIE_0              99
#define DCOOKIE_1              130
#define DCOOKIE_2              83
#define DCOOKIE_3              99
#define DHCP_MSG               53
#define OPTION_LEN             1
#define DHCPDISCOVER           1
#define DHCPOFFER              2
#define DHCPREQUEST            3
#define DHCPACK                5
#define DHCP_END               255



//ETHERNET
#define SMAC_LEN               6
#define DMAC_LEN               6
#define IPv4                   0x0800
#define ETH_DMAC               {0xff,0xff,0xff,0xff,0xff,0xff}

//IP
#define V4                     0x4
#define IHDR_LEN               0x5
#define IPTOS_LOWDELAY         0x10
#define FRAG_OFF               0x00
#define TIME_TO_LIVE           0x40
#define CHECK                  0x00
#define SADDR_IP               "0.0.0.0"
#define DADDR_IP               "255.255.255.255"

//UDP
#define SPORT                 68
#define DPORT                 67

//GENERAL
#define ERROR                  -1
#define ETH_P_ALL              0x0003
#define eth0                   "eth0"
#define wifi0                  "wifi0"
#define PKT_LEN                (sizeof(ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(dhcphdr))
#define ETH                     sizeof(ethhdr)
#define IP                      sizeof(struct iphdr)
#define UDP                     sizeof(struct udphdr)
#define DHCP                    sizeof(dhcphdr)
#define STARV_SUCCESS           5
#define ALTER_PKT_SUCCESSFUL    6
#define ROGUE_SUCCESS           7

#define PCAP_ERRBUF_SIZE        256
#define PCAP_RECV_BUF           65535





#pragma pack(push,1)
typedef struct
{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
}ethhdr;
#pragma pack(pop)




#pragma pack(push,1)
typedef struct
{
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t sec;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[CLIENT_HARDWARE_ADDR];
    uint8_t sname[SNAME];
    uint8_t files[DHCP_FILE_LEN];
    uint8_t mcookie[MCOOKIE_LEN];
    uint8_t options[DHCP_OPTION_LEN];
}dhcphdr;
#pragma pack(pop)



#endif


