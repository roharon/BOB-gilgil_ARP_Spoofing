#pragma once
#include "arp_packet.h"

arp_packet::arp_packet() {
    u_char dest[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    memcpy(this->data.eth.destination, dest,  6);
    u_char source[6] = {0xd0, 0xc6, 0x37, 0xd3, 0x10, 0x0d};
    memcpy(this->data.eth.source, source, 6);
    u_char type[2] = {0x08, 0x06};
    memcpy(this->data.eth.Type, type, 6);
    u_char hat[2] = {0x00, 0x01};
    memcpy(this->data.arp.hat, hat, 2);

    u_char pat[2] = {0x08, 0x00};
    memcpy(this->data.arp.pat, pat, 2);
    u_char hal[1] = {0x06};
    memcpy(this->data.arp.hlen, hal, 1);
    u_char pal[1] = {0x04};
    memcpy(this->data.arp.plen, pal, 1);
    u_char opcode[2] = {0x00, 0x01};
    memcpy(this->data.arp.opcode, opcode, 2);
    u_char sha[6] = {0x3c, 0xf0, 0x11, 0x28, 0x2b, 0xbb};
    memcpy(this->data.arp.srcMAC, sha, 6);
    u_char spa[4] = {0xc0, 0xa8, 0x2b, 0x7,};
    memcpy(this->data.arp.srcIP, spa, 4);
    u_char tha[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(this->data.arp.dstMAC, tha, 6);
    u_char tpa[4] = {0xc0, 0xa8, 0x2b, 51};
    memcpy(this->data.arp.dstIP, tpa, 4);
}

int arp_packet::isARP(const uint8_t* pck){
    if((pck[12] == 0x08) && (pck[13] == 0x06))
        return 1;
    else
        return 0;
}

int arp_packet::isRep(const uint8_t *pck) {
    char OpIsRep = (pck[20]==0x00 && pck[21]==0x02);
    if(OpIsRep){
        return 1;
    }
    return 0;
}

u_char* arp_packet::getDstMac() {
    return this->data.eth.destination;
}

u_char* arp_packet::getSendMac() {
    return this->data.eth.source;
}

void arp_packet::modifyTargetMAC(u_char *value) {
    for(int i = 0; i<MAC_SIZE; i++)
    {
        this->data.arp.dstMAC[i] = value[i];
    }
}

//TODO 아래 코드 작성

void arp_packet::modifySenderMAC(u_char value[]){
     for(int i = 0; i<MAC_SIZE; i++){
         this->data.arp.srcMAC[i] = value[i];
     }
}

void arp_packet::modifyTargetIP(u_char value[]){
    for(int i =0; i<IP_SIZE; i++){
        this->data.arp.dstIP[i] = value[i];
    }
}

void arp_packet::modifySenderIP(u_char *value) {
    for(int i =0; i<IP_SIZE; i++){
        this->data.arp.srcIP[i] = value[i];
    }
}

void arp_packet::modifyOP(int value) {
    unsigned char val_arr[2];
    if(value == ARP_REQUEST){
        val_arr[0] = 0x00;
        val_arr[1] = 0x01;
    }
    else if(value == ARP_REPLY){
        val_arr[0] = 0x00;
        val_arr[1] = 0x02;
    }
    for(int i =0; i<OP_SIZE; i++){
        this->data.arp.opcode[i] = val_arr[i];
    }
}

void arp_packet::modifyETHDestination(u_char *value) {
    for(int i = 0; i<MAC_SIZE; i++){
        this->data.eth.destination[i] = value[i];
    }
}

void arp_packet::modifyETHSource(u_char *value) {
    for(int i =0; i<MAC_SIZE; i++){
        this->data.eth.source[i] = value[i];
    }
}