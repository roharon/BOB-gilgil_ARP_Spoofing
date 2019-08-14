#ifndef BOB_GILGIL_ARP_SPOOFING_ARP_PACKET_H
#define BOB_GILGIL_ARP_SPOOFING_ARP_PACKET_H
#include "stdafx.h"

class arp_packet {
private:
    packet_type data;
public:
    arp_packet();
    ~arp_packet();
    int isARP(const uint8_t* pck);
    int isRep(const uint8_t* pck);
    u_char* getDstMac();
    u_char* getSendMac();
    void modifyTargetMAC(u_char value[]);
    void modifySenderMAC(u_char value[]);
    void modifyTargetIP(u_char value[]);
    void modifySenderIP(u_char value[]);
    void modifyOP(int value);
    void modifyETHDestination(u_char value[]);
    void modifyETHSource(u_char value[]);

    };


#endif //BOB_GILGIL_ARP_SPOOFING_ARP_PACKET_H
