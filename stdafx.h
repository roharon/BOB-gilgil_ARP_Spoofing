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

#include <pthread.h>
#define true 1
#define false 0

#define MAC_SIZE 6
#define IP_SIZE 4
#define OP_SIZE 2
#define ARP_PCK_SIZE 42
#define ARP_REQUEST 0x0001
#define ARP_REPLY 0x0002

typedef struct{
    char sender_ip[4];
    char gateway_ip[4];
}thread_args;
