#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <unistd.h>

char errBuf[PCAP_ERRBUF_SIZE];
char device[50] = {0};

int setDevice() { // setting device to open handler
    pcap_if_t *list;
    pcap_findalldevs(&list, errBuf);
    if (!list) {
        pcap_freealldevs(list);
        printf("Some error with device: %s\n", errBuf);
        return 1;
    }
    strcpy(device, list->name);
    pcap_freealldevs(list);
    return 0;
}

char *generateIP(uint8_t *p) {
    for (int i = 0; i < 4; ++i)
        p[i] = rand() & 0xFF; // we definitely have no reason to use htons, because we have random generated values
    return p; // and no matter if they are in right ethernet order or not
}

char *generateMAC(uint8_t *p) {
    for (int i = 0; i < 6; ++i)
        p[i] = rand() & 0xFF;
    return p;
}

unsigned char *generateReply(unsigned char *result) {
    uint8_t dstIP[4], srcIP[4], dstMAC[6], srcMAC[6];
    //generating random data
    generateIP(dstIP);
    generateIP(srcIP);
    generateMAC(dstMAC);
    generateMAC(srcMAC);
    // setting ethernet header
    struct ether_header header;
    memcpy(header.ether_dhost, dstMAC, sizeof(uint8_t) * 6);
    memcpy(header.ether_shost, srcMAC, sizeof(uint8_t) * 6);
    header.ether_type = htons(ETH_P_ARP);
    // arp body
    struct ether_arp body;
    body.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    body.ea_hdr.ar_pro = htons(ETH_P_IP);
    body.ea_hdr.ar_hln = ETHER_ADDR_LEN;
    body.ea_hdr.ar_pln = sizeof(in_addr_t);
    body.ea_hdr.ar_op = htons(ARPOP_REPLY);
    memcpy(body.arp_tha, dstMAC, sizeof(uint8_t) * 6);
    memcpy(body.arp_sha, srcMAC, sizeof(uint8_t) * 6);
    memcpy(body.arp_tpa, dstIP, sizeof(uint8_t) * 4);
    memcpy(body.arp_spa, srcIP, sizeof(uint8_t) * 4);
    // combining header of ethernet and body of arp reply
    memcpy(result, &header, sizeof(struct ether_header));
    memcpy(result + sizeof(struct ether_header), &body, sizeof(struct ether_arp));
    printf("sending from %d.%d.%d.%d(%d-%d-%d-%d-%d-%d) to %d.%d.%d.%d(%d-%d-%d-%d-%d-%d)\n",
           srcIP[0], srcIP[1], srcIP[2], srcIP[3],
           srcMAC[0], srcMAC[1], srcMAC[2], srcMAC[3], srcMAC[4], srcMAC[5],
           dstIP[0], dstIP[1], dstIP[2], dstIP[3],
           dstMAC[0], dstMAC[1], dstMAC[2], dstMAC[3], dstMAC[4], dstMAC[5]);
    return result;
}

// !!!!!!!  RUN WITH SUDO  !!!!!!!

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("You have to pass as argument number of packets to send\n");
        return 1;
    }
    int count = atoi(argv[1]);
    srand(time(NULL));
    if (setDevice())
        return 1;
    printf("Device is set: %s\n", device);
    pcap_t *p = pcap_open_live(device, 1024, 0, 0, errBuf);
    if (!p) {
        printf("Some error with opening live: %s\n", errBuf);
        return 1;
    }
    unsigned char result[sizeof(struct ether_header) + sizeof(struct ether_arp)];
    for (int i = 0; i < count; ++i) {
        generateReply(result);
        if (pcap_inject(p, result, sizeof(result)) == -1) {
            printf("Some error with sending: %s\n", errBuf);
            pcap_close(p);
            return 1;
        }
        sleep(2); // being nice, otherwise router is banning me(
    }
    pcap_close(p);
    return 0;
}
