#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <cstdint>
#include <string.h>
#include <pcap/pcap.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <zconf.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdint-gcc.h>

#include "arp_packet.h"

#define true 1
#define false 0

#define MAC_SIZE 6
#define IP_SIZE 4
#define OP_SIZE 2
#define ARP_REQUEST 0x0001
#define ARP_REPLY 0x0002
#define ARP_SIZE 42

int getMyMac(u_char* myMac, char* _interface){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, _interface);
    if(!ioctl(fd, SIOCGIFHWADDR, &s)){
        //printf("\n");
        for(int i =0; i<6; i++){
            myMac[i] = s.ifr_addr.sa_data[i];
            //printf("%x ", myMac[i]);
        }
    }
    return 1;
}

void getDstMac(u_char* MAC, const u_char* pck){
    for(int i = 6; i < 12; i++){
        MAC[i-6] = pck[i];
    }
}

void getSendMac(u_char* MAC, const u_char* pck){
    for(int i = 0;i<6;i++){
        MAC[i] = pck[i];
        printf("%x ", MAC[i]);
    }
}