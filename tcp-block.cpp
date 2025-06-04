#include <iostream>
#include <pcap.h>
#include <libnet.h>
#include <unistd.h>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "mac.h"

using namespace std;

#define HTTP_REDIRECT_MSG "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n"

Mac attacker_mac;

unsigned short checksum(unsigned short* buffer, int size) {
    unsigned long cksum = 0;
    while (size > 1) {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if (size)
        cksum += *(unsigned char*)buffer;
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (unsigned short)(~cksum);
}

void send_forward_rst(pcap_t* handle, const u_char* packet, struct libnet_ipv4_hdr* iphdr, struct libnet_tcp_hdr* tcphdr, int data_len, uint8_t* my_mac) {
    int eth_len = LIBNET_ETH_H;
    int ip_len = iphdr->ip_hl * 4;
    int tcp_len = tcphdr->th_off * 4;
    int pkt_len = eth_len + ip_len + tcp_len;

    u_char rst_pkt[pkt_len];
    memcpy(rst_pkt, packet, pkt_len);

    struct libnet_ethernet_hdr* eth = (struct libnet_ethernet_hdr*)rst_pkt;
    memcpy(eth->ether_shost, my_mac, 6);

    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)(rst_pkt + eth_len);
    ip->ip_len = htons(ip_len + tcp_len);
    ip->ip_sum = 0;
    ip->ip_sum = checksum((unsigned short*)ip, ip_len);

    struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)(rst_pkt + eth_len + ip_len);
    tcp->th_seq = htonl(ntohl(tcp->th_seq) + data_len);
    tcp->th_flags = TH_RST | TH_ACK;
    tcp->th_sum = 0;

    // pseudo-header
    u_char pseudo[12 + tcp_len];
    memcpy(pseudo, &ip->ip_src.s_addr, 4);
    memcpy(pseudo + 4, &ip->ip_dst.s_addr, 4);
    pseudo[8] = 0;
    pseudo[9] = IPPROTO_TCP;
    uint16_t tcp_size = htons(tcp_len);
    memcpy(pseudo + 10, &tcp_size, 2);
    memcpy(pseudo + 12, tcp, tcp_len);

    tcp->th_sum = checksum((unsigned short*)pseudo, 12 + tcp_len);

    if (pcap_sendpacket(handle, rst_pkt, pkt_len) != 0)
        cerr << "[-] Failed to send RST: " << pcap_geterr(handle) << endl;
}

void send_backward_fin(struct libnet_ipv4_hdr* iphdr, struct libnet_tcp_hdr* tcphdr, int data_len) {
    const char* payload = HTTP_REDIRECT_MSG;
    int payload_len = strlen(payload);
    int ip_len = iphdr->ip_hl * 4;
    int tcp_len = tcphdr->th_off * 4;
    int pkt_len = ip_len + tcp_len + payload_len;

    u_char pkt[pkt_len];
    memset(pkt, 0, pkt_len);

    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)pkt;
    struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)(pkt + ip_len);
    char* data = (char*)(pkt + ip_len + tcp_len);

    // IP
    ip->ip_hl = iphdr->ip_hl;
    ip->ip_v = 4;
    ip->ip_ttl = 64;
    ip->ip_p = IPPROTO_TCP;
    ip->ip_len = htons(pkt_len);
    ip->ip_src = iphdr->ip_dst;
    ip->ip_dst = iphdr->ip_src;
    ip->ip_sum = 0;
    ip->ip_sum = checksum((unsigned short*)ip, ip_len);

    // TCP
    tcp->th_sport = tcphdr->th_dport;
    tcp->th_dport = tcphdr->th_sport;
    tcp->th_seq = tcphdr->th_ack;
    tcp->th_ack = htonl(ntohl(tcphdr->th_seq) + data_len);
    tcp->th_off = tcp_len / 4;
    tcp->th_flags = TH_FIN | TH_ACK | TH_PUSH;
    tcp->th_win = htons(1024);
    memcpy(data, payload, payload_len);

    // pseudo-header
    u_char pseudo[12 + tcp_len + payload_len];
    memcpy(pseudo, &ip->ip_src.s_addr, 4);
    memcpy(pseudo + 4, &ip->ip_dst.s_addr, 4);
    pseudo[8] = 0;
    pseudo[9] = IPPROTO_TCP;
    uint16_t tcp_size = htons(tcp_len + payload_len);
    memcpy(pseudo + 10, &tcp_size, 2);
    memcpy(pseudo + 12, tcp, tcp_len);
    memcpy(pseudo + 12 + tcp_len, data, payload_len);

    tcp->th_sum = 0;
    tcp->th_sum = checksum((unsigned short*)pseudo, 12 + tcp_len + payload_len);

    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    int opt = 1;
    setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = ip->ip_dst.s_addr;

    if (sendto(sd, pkt, pkt_len, 0, (sockaddr*)&dst, sizeof(dst)) < 0)
        perror("sendto failed");
    close(sd);
}

bool get_attacker_mac(const char* dev) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;

    struct ifreq ifr;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(fd);
        return false;
    }

    attacker_mac = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
    close(fd);
    return true;
}

void usage() {
    cout << "syntax : tcp-block <interface> <pattern>\n";
    cout << "sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n";
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    const char* pattern = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        cerr << "pcap_open_live failed: " << errbuf << endl;
        return -1;
    }

    if (!get_attacker_mac(dev)) {
        cerr << "Failed to get MAC address" << endl;
        return -1;
    }
    cout << "[*] Attacker MAC: " << string(attacker_mac) << endl;

    cout << "[*] TCP block start on " << dev << endl;
    struct pcap_pkthdr* header;
    const u_char* packet;
    while (true) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res <= 0) continue;

        // ethernet header + ip header + tcp header + tcp data
        struct libnet_ethernet_hdr* eth = (struct libnet_ethernet_hdr*)packet;
        if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
            cout << "[-] Not IPv4 Packet" << endl;
            continue;
        }
        uint32_t ethdr_len = LIBNET_ETH_H;

        struct libnet_ipv4_hdr* iphdr = (struct libnet_ipv4_hdr*)(packet + ethdr_len);
        if (iphdr->ip_p != IPPROTO_TCP) {
            cout << "[-] Not TCP Packet" << endl;
            continue;
        }
        uint32_t iphdr_len = (iphdr->ip_hl) * 4;

        struct libnet_tcp_hdr* tcphdr = (struct libnet_tcp_hdr*)((uint8_t*)iphdr + iphdr_len);
        int tcphdr_len = (tcphdr->th_off) * 4;

        const char* data = (const char*)(packet + ethdr_len + iphdr_len + tcphdr_len);
        int data_len = ntohs(iphdr->ip_len) - iphdr_len - tcphdr_len;
        if (data_len <= 0) continue;

        if (strncmp(data, "GET", 3) == 0 && memmem(data, data_len, pattern, strlen(pattern)) != NULL) {
            cout << "[+] Pattern matched. Sending block packets..." << endl;
            send_backward_fin(iphdr, tcphdr, data_len);
            send_forward_rst(handle, packet, iphdr, tcphdr, data_len, (uint8_t*)attacker_mac);
        }
    }

    pcap_close(handle);
    return 0;
}
