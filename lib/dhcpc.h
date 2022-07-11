#include <netinet/ip_icmp.h>	//Provides declarations for icmp header
#include <netinet/udp.h>	//Provides declarations for udp header
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header
#include <netinet/if_ether.h>	//For ETH_P_ALL
#include <net/ethernet.h>	//For ether_header
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <string.h>
#include <stdlib.h>

//
#define MAC_BCAST_ADDR      (unsigned char *) "/xff/xff/xff/xff/xff/xff"

// ref : busybox -> networking -> udhcp -> common.h 
// define the structure of DHCP message

#define PACKED __attribute__((__packed__))

/* DHCP protocol. See RFC 2131 */
#define DHCP_MAGIC              0x63825363
#define DHCP_OPTIONS_BUFSIZE    308
#define BOOTREQUEST             1
#define BOOTREPLY               2
#define DHCP_CLIENT_PORT        68
#define DHCP_SERVER_PORT        67

struct dhcp_packet {
    uint8_t op;      /* BOOTREQUEST or BOOTREPLY */
    uint8_t htype;   /* hardware address type. 1 = 10mb ethernet */
    uint8_t hlen;    /* hardware address length */
    uint8_t hops;    /* used by relay agents only */
    uint32_t xid;    /* unique id */
    uint16_t secs;   /* elapsed since client began acquisition/renewal */
    uint16_t flags;  /* only one flag so far: */
#define BROADCAST_FLAG 0x8000 /* "I need broadcast replies" */
    uint32_t ciaddr; /* client IP (if client is in BOUND, RENEW or REBINDING state) */
    uint32_t yiaddr; /* 'your' (client) IP address */
    /* IP address of next server to use in bootstrap, returned in DHCPOFFER, DHCPACK by server */
    uint32_t siaddr_nip;
    uint32_t gateway_nip; /* relay agent IP address */
    uint8_t chaddr[16];   /* link-layer client hardware address (MAC) */
    uint8_t sname[64];    /* server host name (ASCIZ) */
    uint8_t file[128];    /* boot file name (ASCIZ) */
    uint32_t cookie;      /* fixed first four option bytes (99,130,83,99 dec) */
    uint8_t options[DHCP_OPTIONS_BUFSIZE];
} PACKED;

#define DHCP_PKT_SNAME_LEN      64
#define DHCP_PKT_FILE_LEN      128
#define DHCP_PKT_SNAME_LEN_STR "64"
#define DHCP_PKT_FILE_LEN_STR "128"

/* DHCP_MESSAGE_TYPE values */
#define DHCPDISCOVER            1 /* client -> server */
#define DHCPOFFER               2 /* client <- server */
#define DHCPREQUEST             3 /* client -> server */
#define DHCPDECLINE             4 /* client -> server */
#define DHCPACK                 5 /* client <- server */
#define DHCPNAK                 6 /* client <- server */
#define DHCPRELEASE             7 /* client -> server */
#define DHCPINFORM              8 /* client -> server */
#define DHCP_MINTYPE DHCPDISCOVER
#define DHCP_MAXTYPE DHCPINFORM

static const char * const DHCP_MESSAGE_TYPE_DICT[] = {
    [DHCPDISCOVER]= "DHCPDISCOVER",
    [DHCPOFFER]= "DHCPOFFER",
    [DHCPREQUEST]= "DHCPREQUEST",
    [DHCPDECLINE]= "DHCPDECLINE",
    [DHCPACK]= "DHCPACK",
    [DHCPNAK]= "DHCPNAK",
    [DHCPRELEASE]= "DHCPRELEASE",
    [DHCPINFORM]= "DHCPINFORM",
};

struct ip_udp_dhcp_packet {
	struct iphdr ip;
	struct udphdr udp;
	struct dhcp_packet data;
} PACKED;

struct udp_dhcp_packet {
	struct udphdr udp;
	struct dhcp_packet data;
} PACKED;

enum {
	IP_UDP_DHCP_SIZE = sizeof(struct ip_udp_dhcp_packet),
	UDP_DHCP_SIZE    = sizeof(struct udp_dhcp_packet),
	DHCP_SIZE        = sizeof(struct dhcp_packet),
};

/* DHCP option codes (partial list). See RFC 2132 and
 * http://www.iana.org/assignments/bootp-dhcp-parameters/
 * Commented out options are handled by common option machinery,
 * uncommented ones have special cases (grep for them to see).
 */
#define DHCP_PADDING            0x00
#define DHCP_SUBNET             0x01
//#define DHCP_TIME_OFFSET      0x02 /* (localtime - UTC_time) in seconds. signed */
//#define DHCP_ROUTER           0x03
//#define DHCP_TIME_SERVER      0x04 /* RFC 868 time server (32-bit, 0 = 1.1.1900) */
//#define DHCP_NAME_SERVER      0x05 /* IEN 116 _really_ ancient kind of NS */
//#define DHCP_DNS_SERVER       0x06
//#define DHCP_LOG_SERVER       0x07 /* port 704 UDP log (not syslog)
//#define DHCP_COOKIE_SERVER    0x08 /* "quote of the day" server */
//#define DHCP_LPR_SERVER       0x09
#define DHCP_HOST_NAME          0x0c /* 12: either client informs server or server gives name to client */
//#define DHCP_BOOT_SIZE        0x0d
//#define DHCP_DOMAIN_NAME      0x0f /* 15: server gives domain suffix */
//#define DHCP_SWAP_SERVER      0x10
//#define DHCP_ROOT_PATH        0x11
//#define DHCP_IP_TTL           0x17
//#define DHCP_MTU              0x1a
//#define DHCP_BROADCAST        0x1c
//#define DHCP_ROUTES           0x21
//#define DHCP_NIS_DOMAIN       0x28
//#define DHCP_NIS_SERVER       0x29
//#define DHCP_NTP_SERVER       0x2a
//#define DHCP_WINS_SERVER      0x2c
#define DHCP_REQUESTED_IP       0x32 /* 50: sent by client if specific IP is wanted */
#define DHCP_LEASE_TIME         0x33 /* 51: */
#define DHCP_OPTION_OVERLOAD    0x34 /* 52: */
#define DHCP_MESSAGE_TYPE       0x35 /* 53: */
#define DHCP_SERVER_ID          0x36 /* 54: server's IP */
#define DHCP_PARAM_REQ          0x37 /* 55: list of options client wants */
//#define DHCP_ERR_MESSAGE      0x38 /* 56: error message when sending NAK etc */
#define DHCP_MAX_SIZE           0x39 /* 57: */
#define DHCP_VENDOR             0x3c /* 60: client's vendor (a string) */
#define DHCP_CLIENT_ID          0x3d /* 61: by default client's MAC addr, but may be arbitrarily long */
//#define DHCP_TFTP_SERVER_NAME 0x42 /* 66: same as 'sname' field */
//#define DHCP_BOOT_FILE        0x43 /* 67: same as 'file' field */
//#define DHCP_USER_CLASS       0x4d /* 77: RFC 3004. set of LASCII strings. "I am a printer" etc */
#define DHCP_FQDN               0x51 /* 81: client asks to update DNS to map its FQDN to its new IP */
//#define DHCP_DOMAIN_SEARCH    0x77 /* 119: RFC 3397. set of ASCIZ string, DNS-style compressed */
//#define DHCP_SIP_SERVERS      0x78 /* 120: RFC 3361. flag byte, then: 0: domain names, 1: IP addrs */
//#define DHCP_STATIC_ROUTES    0x79 /* 121: RFC 3442. (mask,ip,router) tuples */
//#define DHCP_VLAN_ID          0x84 /* 132: 802.1P VLAN ID */
//#define DHCP_VLAN_PRIORITY    0x85 /* 133: 802.1Q VLAN priority */
//#define DHCP_PXE_CONF_FILE    0xd1 /* 209: RFC 5071 Configuration File */
//#define DHCP_PXE_PATH_PREFIX  0xd2 /* 210: RFC 5071 Configuration File */
//#define DHCP_REBOOT_TIME      0xd3 /* 211: RFC 5071 Reboot time */
//#define DHCP_MS_STATIC_ROUTES 0xf9 /* 249: Microsoft's pre-RFC 3442 code for 0x79? */
//#define DHCP_WPAD             0xfc /* 252: MSIE's Web Proxy Autodiscovery Protocol */
#define DHCP_END                0xff /* 255: */


// declare functions

/**
 * @brief Create a socket fd to send DHCP message
 *
 * @param[in,out] send_sockfd sockfd for sending DHCP mesaage
 * @param[in] interface  
 * @param[in,out] send_sockaddr sockaddr for broadcasting DHCP message
 * @retval 0 sucessfully 
 */
int create_dhcpc_send_socket(int * send_sockfd, char * interface, struct sockaddr_ll * send_sockaddr);

/**
 * @brief Create a socket fd to receive DHCP message
 * 
 * @param[in,out] receive_sockfd sockfd for receiving DHCP message
 * @param[in] interface  
 * @param[in,out] receive_sockaddr sockaddr for receiving DHCP message
 * @retval 0 sucessfully 
 */
int create_dhcpc_receive_socket(int * receive_sockfd, char * interface, struct sockaddr_ll * receive_sockaddr);

/**
 * @brief send DHCP discovery message
 * 
 * @param[in] send_sockfd socket_fd for sending message
 * @param[in] interface select the interface to send DHCP discovery message.
 * @param[in] send_sockaddr the destination sockaddress. ( the packet whould send to that address )
 * @param[in] xid transaction id 
 * @retval 0 send sucessfully
 */
int send_discovery(int send_sockfd, char * interface, struct sockaddr_ll send_sockaddr, uint32_t xid);

/**
 * @brief receive DHCP offer message
 * 
 * @param[in] receive_sockfd socket_fd for receiving message
 * @param[in] receive_sockaddr the source sockaddress. ( the packet that received from that address )
 * @param[in] xid transaction id
 * @param[in,out] received_packet received packet including iphdr, udphdr, and dhcp_packet. 
 * @retval 0 receive sucessfully
 */
int receive_offer(int receive_sockfd, struct sockaddr_ll receive_sockaddr, uint32_t xid, struct ip_udp_dhcp_packet * received_packet);

/**
 * @brief Get the information of internet interface including MAC, and ifindex. 
 * 
 * @param[in] interface the name of interface (e.g. eth0 ) 
 * @param[out] mac  the MAC number.
 * @param[out] ifindex  the value of ifindex.
 * @retval 0 get information sucessfully
 */
int get_interface_config(const char * interface, uint8_t * mac, int * ifindex);

/**
 * @brief Calculate how many padding zero behind DHCP_END(0xff)
 * 
 * @param[in] packet the packet including iphdr, udphdr, and DHCP payload.
 * @param[out] padding the number of padding zeros behind DHCP_END(0xff).
 * @retval 0 sucessfully
 */
int get_padding(struct ip_udp_dhcp_packet * packet, int * padding); // 

/**
 * @brief Do checksum
 * 
 * reference : from busybox/libbb/inet_cksum.c
 * 
 * @param[in] addr the address of the head of header. 
 * @param[in] nleft the size of the header.
 * @return checksum value 
 */
uint16_t inet_cksum(uint16_t *addr, int nleft); 

/**
 * @brief Get the specific DHCP option information
 * 
 * @param[in] packet dhcp packet including ip, udp, and dhcp payload.
 * @param[in] desired_option_key the option key that you want
 * @param[in,out] p_option_data the address points to the address of option data container.
 * @param[in,out] option_data_len the length of the specific option value 
 * @return int 
 */
int get_specific_option_data(struct ip_udp_dhcp_packet * packet, int desired_option_key, uint8_t ** p_option_data, int * option_data_len);