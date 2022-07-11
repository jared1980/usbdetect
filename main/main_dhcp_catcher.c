#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <poll.h>
#include <fcntl.h>
#include <getopt.h>
#include <time.h>
#include "dhcpc.h"

#define POLL_RECEIVE_PACKET

int FLAG_VERBOSE = 0; /* Definition FLAG_VERBOSE, global variable */

void HELP(int argc, char * argv[]){
    printf("\n");
    printf("%s: %s -i %s\n", "usage", argv[0], "<interface>");
    printf("argument:\n");
    printf("\t%s: %s\n", "<interface>", "specify interface");
    printf("\n");
}

int main(int argc, char * argv[]){

    // declare variables
    uint32_t xid = 0;
    struct pollfd pfds[1];
    struct ip_udp_dhcp_packet received_packet;
    int send_sockfd, receive_sockfd;
    struct sockaddr_ll send_sockaddr, receive_sockaddr;
    uint8_t * desired_option_value = NULL;
    int desired_option_len = 0;
    int poll_ret = 0;
    int ret = 0;
    const int timeout = 3;
    char interface[16];
    int option_index = 0;

    // initializatipn
    memset( interface, 0x00, sizeof(interface) );

    // argument checking
    if ( argc != 3 ){
        memcpy(interface, "eth0", 4);
    }

    // argument parsing
    while (( option_index = getopt(argc, argv, "i:v")) != -1 ){
        switch (option_index)
        {
        case 'i':
            memcpy(interface, optarg, strlen(optarg));
            break;

        case 'v':
            FLAG_VERBOSE = 1;
            break;
        
        default:
            HELP(argc, argv);
            return 1;
        }
    }

    // display interface
	printf("interface : %s\n", interface);

    // set random seed
    srand( time(NULL) );
    xid = rand();

    // create send sockfd and send destination addres
    create_dhcpc_send_socket(&send_sockfd, interface, &send_sockaddr);

    // create receive sockfd
    create_dhcpc_receive_socket(&receive_sockfd, interface, &receive_sockaddr);

    // while(1) loop
    while(1){

        // reset sockfd status
        fcntl(receive_sockfd, F_SETFD, FD_CLOEXEC);
        pfds[0].fd      = receive_sockfd;
        pfds[0].events  = POLLIN;
        pfds[0].revents = 0;

        // poll rcev
        poll_ret = poll((struct pollfd *)&pfds, 1, timeout);

        /* send DHCP discovery frame */
        if ( poll_ret == 0 ){
            printf("send discovery\n");
            send_discovery(send_sockfd, interface, send_sockaddr, xid);
       	    sleep(3);
        } 
        
        /* receive DHCP offer frame */
        if ( (poll_ret == 1) && (pfds[0].revents == 1) ){
            
            // receive DHCP offer
            ret = receive_offer(receive_sockfd, receive_sockaddr, xid, &received_packet);

            // parse dhcp option content
            if ( ret != 0 ){
                printf("receive NON-DHCP packet\n");
            } else {
                get_specific_option_data(&received_packet, 43, &desired_option_value, &desired_option_len);

                printf("option %d -> ", 43);
                for( int i=0; i<desired_option_len; i++ ){
                    printf("%02x ", desired_option_value[i]);
                }
                printf("\n");
                break;
            }
        }
    }

    // release
    free(desired_option_value); // it belongs heap memory and is generated in the function, "get_specific_option_data".
    close(send_sockfd);
    close(receive_sockfd);
            
    return 0;
}
