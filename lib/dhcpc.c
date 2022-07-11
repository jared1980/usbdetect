#include "dhcpc.h"
#include <stdio.h>
#include <errno.h>

#define DIVISION_LIN_STRING "========================%s==============================\n"

extern int errno;

// <<< verbose function START
#include <stdarg.h>
extern int FLAG_VERBOSE; // declare global extern variable
int verbose(const char * restrict format, ...) {
    if( !FLAG_VERBOSE )
        return 0;

    va_list args;
    va_start(args, format);
    int ret = vprintf(format, args);
    va_end(args);

    return ret;
}
// <<< verbose function END

int create_dhcpc_send_socket(int * send_sockfd, char * interface, struct sockaddr_ll * send_sockaddr){

    // declare variables
    struct sockaddr_ll dest_sockaddr;
    uint8_t mac[6];
    int ifindex;
    int fd;
    int ret;

    // initialize
    memset(&dest_sockaddr, 0x00, sizeof(struct sockaddr_ll));
    memset(&mac, 0x00, sizeof(mac));

    // get the interface mac and ifindex
    get_interface_config(interface, (uint8_t*)&mac, &ifindex);

    /* socket fd initialization */
    // apply socket fd 
    fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    if ( fd < 0 ){
        perror("sock() failed");
        return -1;
    }

    // fill server address
    dest_sockaddr.sll_family     = AF_PACKET;
    dest_sockaddr.sll_protocol   = htons(ETH_P_IP);
    dest_sockaddr.sll_ifindex    = ifindex;
    // dest_sockaddr.sll_hatype     = APRHRD_???;
    // dest_sockaddr.sll_pkttype    = PACKET_???;
    memset(dest_sockaddr.sll_addr, MAC_BCAST_ADDR, 6);
    dest_sockaddr.sll_halen      = 6;

    // bind socket 
    ret = bind(fd, (const struct sockaddr *)&dest_sockaddr, sizeof(dest_sockaddr));
    if ( ret < 0 ){
        perror("bind() failed");
        return -2;
    }

    // output sockfd and sockaddr
    *send_sockfd = fd;
    *send_sockaddr = dest_sockaddr;

    return 0;
}

int create_dhcpc_receive_socket(int * receive_sockfd, char * interface, struct sockaddr_ll * receive_sockaddr){

    // declare variables
    struct sockaddr_ll src_sockaddr;
    uint8_t mac[6];
    int ifindex;
    int fd;
    int ret;

    // initialize
    memset(&src_sockaddr, 0x00, sizeof(struct sockaddr_ll));
    memset(&mac, 0x00, sizeof(mac));

    // get the interface mac and ifindex
    get_interface_config(interface, &mac, &ifindex);

    /* socket fd initialization */
    // apply socket fd 
    fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    if ( fd < 0 ){
        perror("sock() failed");
        return -1;
    }

    // fill server address
    src_sockaddr.sll_family     = AF_PACKET;
    src_sockaddr.sll_protocol   = htons(ETH_P_IP);
    src_sockaddr.sll_ifindex    = ifindex;
    // src_sockaddr.sll_hatype     = APRHRD_???;
    // src_sockaddr.sll_pkttype    = PACKET_???;
    // memset(src_sockaddr.sll_addr, MAC_BCAST_ADDR, 6);
    // src_sockaddr.sll_halen      = 6;

    // bind socket 
    ret = bind(fd, (const struct sockaddr *)&src_sockaddr, sizeof(src_sockaddr));
    if ( ret < 0 ){
        perror("bind() failed");
        return -2;
    }

    // output sockfd and sockaddr
    *receive_sockfd = fd;
    *receive_sockaddr = src_sockaddr;

    return 0;
}

int send_discovery(int send_sockfd, char * interface, struct sockaddr_ll send_sockaddr, uint32_t xid){

    // declare variables
    // struct sockaddr_ll dest_sll;
    struct ip_udp_dhcp_packet packet;
    socklen_t len = 0;
    int ifindex = 0;
    uint8_t mac[6];
    // int fd;
    int ret = 0;
    int padding = 0;

    // initial variables
    // memset(&dest_sll, 0x00, sizeof(struct sockaddr_ll));
    memset(&packet, 0x00, sizeof(struct ip_udp_dhcp_packet));

    // get the interface mac and ifindex
    get_interface_config(interface, &mac, &ifindex);

    /* assign value to UDP payload (DHCP data) */
    packet.data.op       = BOOTREQUEST;
    packet.data.htype    = 1; // ethernet
    packet.data.hlen     = 6;
    packet.data.hops     = 0;
    packet.data.xid      = xid;
    packet.data.secs     = 0;
    // packet.flags    = 
    // packet.ciaddr   = 
    // packet.yiaddr   =
    // packet.siaddr_nip   =
    // packet.gateway_nip  = 
    // packet.chaddr   =  
    memcpy(&packet.data.chaddr, &mac, 6);
    // packet.sname    = 
    // packet.file     =
    packet.data.cookie = htonl(DHCP_MAGIC);

    packet.data.options[0] = DHCP_MESSAGE_TYPE;
    packet.data.options[1] = 1;
    packet.data.options[2] = DHCPDISCOVER;

    packet.data.options[3] = DHCP_END;

    /* assign ip and udp header */
    
    // calculate the total size of packet with DHCP payload 
    ret = get_padding(&packet, &padding);
    if( ret != 0 ){
        printf("Padding over bound!!\n");
        return -3;
    }

    // printf("padding = %d\n", padding);

    // assign partial ip header to make pseudo ip header
    packet.ip.protocol  = IPPROTO_UDP;
    packet.ip.saddr     = INADDR_ANY;
    packet.ip.daddr     = INADDR_BROADCAST;
    packet.ip.tot_len   = htons(UDP_DHCP_SIZE - padding); // length UDP length (pseudo ip header use) 
    // packet.ip.ihl       = sizeof(struct iphdr) >> 2;
    // packet.ip.version   = IPVERSION;
    // packet.ip.ttl       = IPDEFTTL;
    // packet.ip.check     = 0;

    // assign udp header
    packet.udp.source   = htons(DHCP_CLIENT_PORT);
    packet.udp.dest     = htons(DHCP_SERVER_PORT);
    packet.udp.len      = htons(UDP_DHCP_SIZE - padding);
    packet.udp.check    = inet_cksum((uint16_t*)&packet, IP_UDP_DHCP_SIZE - padding);

    // complete ip header
    packet.ip.tot_len   = htons(IP_UDP_DHCP_SIZE - padding);
    packet.ip.ihl       = sizeof(struct iphdr) >> 2;
    packet.ip.version   = IPVERSION;
    packet.ip.ttl       = IPDEFTTL;
    packet.ip.check     = inet_cksum((uint16_t*)&packet.ip, sizeof(struct iphdr));


    /* send broadcast packet */
    ssize_t n = 0;
    n = sendto(send_sockfd, &packet, IP_UDP_DHCP_SIZE - padding, MSG_DONTWAIT , (const struct sockaddr *)&send_sockaddr, sizeof(struct sockaddr_ll));
    // printf("n = %d\n", n);
    // printf("len = %d\n", len);
    if ( n < 0 ){
        perror("sendto() failed");
    }

    /* close file descriptor */
    // close(send_sockfd);

    return 0;
}

int receive_offer(int receive_sockfd, struct sockaddr_ll receive_sockaddr, uint32_t xid, struct ip_udp_dhcp_packet * received_packet){

    // declare variables
    int bytes = 0;
    struct msghdr msg;
    struct iovec iov;
    struct cmsghdr *cmsg;
    struct ip_udp_dhcp_packet packet;

    // initialization
    memset(&msg, 0x00, sizeof(msg));

    // assignment
    iov.iov_base = &packet;
    iov.iov_len = sizeof(packet);

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    // msg.msg_control =
    // msg.msg_controllen = 

    // receive packet 
    for(;;){
        bytes = recvmsg(receive_sockfd, &msg, 0);
        printf("received packet bytes: %d\n", bytes);
        if ( bytes < 0 ){
            if ( errno == EINTR ){
                continue;
            }
            return bytes;
        }
        break;
    }

    // dump ip-udp-dhcp packet information
    verbose("packet size        ---> %d\n", bytes);
    verbose("ip:protocol        ---> %d\n", packet.ip.protocol);
    verbose("udp:size(+padding) ---> %d\n", ntohs(packet.udp.len));
    verbose("udp:src port       ---> SRC  PORT (%u)\n", ntohs(packet.udp.source));
    verbose("udp:dest port      ---> DEST PORT (%u)\n", ntohs(packet.udp.dest));
    
    // dump ip-udp-dhcp packet data
    int i=0;
    uint8_t value;
    for( i=0; i<bytes; i++ ){

        value = *((uint8_t*)&packet + i);

        if( i%16 == 0 ){
            verbose("\n");
        } else if ( i%8 == 0 ){
            verbose("\t");
        }

        verbose("%02x ", value);
    }
    verbose("\n");

    // check if it is DHCP message
    int is_dhcp_cookie = ( packet.data.cookie == htonl(DHCP_MAGIC) );
    int is_dhcp_size = ( ntohs(packet.udp.len) > 248 ); // 248 bytes is the size of dhcp message without option content.
    int is_udp = ( packet.ip.protocol == IPPROTO_UDP );

    if ( !is_dhcp_cookie || !is_dhcp_size || !is_udp ){
        return -1;
    }

    // output packet
    *received_packet = packet;

    return 0;
}

int get_interface_config(const char * interface, uint8_t * mac, int * ifindex){

    // declare variables
    struct sockaddr_in * addr;
    struct ifreq ifr;
    int fd;
    int ret = 0;

    // initial
    memset(&ifr, 0x00, sizeof(struct ifreq));

    // apply socket
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if ( fd < 0 ){
        perror("socket() failed");
        return -1;
    }

    // fill the necessary member of interface request(ifr) struct 
    ifr.ifr_addr.sa_family = AF_INET;
    strcpy(ifr.ifr_name, interface);

    // get the mac from the specific interface
    if (mac){
        ret = ioctl(fd, SIOCGIFHWADDR, &ifr);
        if ( ret != 0 ){
            perror("ioctl() failed");
            close(fd);
            return -2;
        }
        memcpy(mac, &ifr.ifr_hwaddr.sa_data, 6);
    }

    // get the ifindex from the specific interface
    if (ifindex){
        ret = ioctl(fd, SIOCGIFINDEX, &ifr);
        if ( ret != 0 ){
            perror("ioctl() failed");
            close(fd);
            return -3;
        }
        *ifindex = ifr.ifr_ifindex;
    }

    // printf(DIVISION_LIN_STRING, "(BEGIN)get mac and ifindex");
    // printf("MAC %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    // printf("ifindex %d\n", *ifindex);
    // printf(DIVISION_LIN_STRING, "(END)get mac and ifindex");
    
    close(fd);
    return 0;
}

int get_padding(struct ip_udp_dhcp_packet * packet, int * padding){

    // declare variable
    uint8_t value = 0x00;
    int offset = sizeof(struct ip_udp_dhcp_packet) - 1;
	
    //
    while( 1 ){
        value = *((uint8_t*)packet + offset );
        if ( offset <= sizeof(struct iphdr) + sizeof(struct udphdr) ){
            *padding = 0;
            return -1;
        } else if ( value == DHCP_END ){
            break;
        } else {
            offset = offset - 1;
        }
    }

    //
    *padding = sizeof(struct ip_udp_dhcp_packet) - 1 - offset;

    return 0;

}

int get_specific_option_data(struct ip_udp_dhcp_packet * packet, int desired_option_key, uint8_t ** p_option_data, int * option_data_len){

    // check argument
    if ( packet == NULL ){
        printf("%s failed\n", __func__);
        return -1;
    }

    // declare variables
    int i=0;
    int flag=0; // 0:has option; -1:;
    uint8_t option_key;
    uint8_t option_len; 
    // uint8_t value=0;
    uint8_t * pOptions=NULL;

    // 
    pOptions = (uint8_t*)&(packet->data.options);

    // find the address of desired option key
    for(;;){

        option_key = *(pOptions);

        if ( option_key == DHCP_END ){
            flag = -1;
            break;
        } else if ( option_key == desired_option_key ){
            flag = 0;
            option_len = *(pOptions + 1);
            break;
        } else {
            option_len = *(pOptions + 1);
            pOptions = pOptions + 2 + option_len;
        }

    }

    // find out desired option and assign data to container
    if ( flag == 0 ){
        // allocate memory for storing option data
        *p_option_data = (uint8_t*) malloc( sizeof(uint8_t) * option_len );
        if ( *p_option_data == NULL ){
            printf("malloc() failed in %s\n", __func__);
            perror("malloc() failed");
        } 

        // output option data and length of option data
        memcpy(*p_option_data, pOptions+2, option_len);
        *option_data_len = option_len;

        // dump
        // printf("desired option key : %d ->", desired_option_key);
        // for( i=0; i<option_len; i++ ){
        //     printf("%#02x ", *(pOptions + 2 + i));
        // }
        // printf("\n");
    }

    return flag;
}

uint16_t inet_cksum(uint16_t *addr, int nleft)
{
	/*
	 * Our algorithm is simple, using a 32 bit accumulator,
	 * we add sequential 16 bit words to it, and at the end, fold
	 * back all the carry bits from the top 16 bits into the lower
	 * 16 bits.
	 */
	unsigned sum = 0;
	while (nleft > 1) {
		sum += *addr++;
		nleft -= 2;
	}

	/* Mop up an odd byte, if necessary */
	if (nleft == 1) {
		if (__BYTE_ORDER == __LITTLE_ENDIAN)
			sum += *(uint8_t*)addr;
		else
			sum += *(uint8_t*)addr << 8;
	}

	/* Add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
	sum += (sum >> 16);                     /* add carry */

	return (uint16_t)~sum;
}
