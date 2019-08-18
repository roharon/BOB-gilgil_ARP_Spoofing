#pragma once
#include "stdafx.h"

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

class arp_packet {
private:
public:
    packet_type data;

    arp_packet();
    ~arp_packet();
    int isARP();
    int isRep();
    int isReq();
    u_char* getDstMac();
    u_char* getSendMac();
    u_char* getSendIP();
    u_char* getDstIP();
    void modifyTargetMAC(u_char value[]);
    void modifySenderMAC(u_char value[]);
    void modifyTargetIP(u_char value[]);
    void modifySenderIP(u_char value[]);
    void modifyOP(int value);
    void modifyETHDestination(u_char value[]);
    void modifyETHSource(u_char value[]);
    void initPacket(u_char value[]);

    };

