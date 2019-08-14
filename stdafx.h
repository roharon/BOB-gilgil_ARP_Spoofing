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

#define true 1
#define false 0

#define MAC_SIZE 6
#define IP_SIZE 4
#define OP_SIZE 2
#define ARP_REQUEST 0x0001
#define ARP_REPLY 0x0002

typedef struct{
    u_char hat[2]; // Hardware address Type - 2byte
    u_char pat[2]; // Protocol address Type - 2byte
    u_char hlen[1]; // Hardware address's length - 1byte
    u_char plen[1]; // protocol address's length - 1byte
    u_char opcode[2]; // reply & request - 2byte
    u_char srcMAC[6]; // source protocol address - 6byte
    u_char srcIP[4]; // Source protocol Address - 4byte
    u_char dstMAC[6]; // destination protocol address - 6byte
    u_char dstIP[4]; // destination protocol address - 4byte

}ARP_hdr;

typedef struct{
    u_char destination[6];
    u_char source[6];
    u_char Type[2];
}ETHER_hdr;

typedef struct{
    ETHER_hdr eth;
    ARP_hdr arp;
}packet_type;


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