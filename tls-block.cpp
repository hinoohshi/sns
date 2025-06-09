#include "tls-block.h"

using namespace std;

Mac attacker_mac;
int sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
map<Key, string> segment_map;

const char* extract_sni(const uint8_t* data, size_t len) {
    size_t pos = sizeof(TlsRecordHeader) + sizeof(TlsHandshakeHeader);
    if (len <= pos + 34) return nullptr;
    pos += 34;

    // Session ID
    if (pos + 1 > len) return nullptr;
    uint8_t session_id_len = data[pos];
    pos += 1;
    if (pos + session_id_len > len) return nullptr;
    pos += session_id_len;

    // Cipher Suites
    if (pos + 2 > len) return nullptr;
    uint16_t cipher_suites_len = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    if (pos + cipher_suites_len > len) return nullptr;
    pos += cipher_suites_len;

    // Compression Methods
    if (pos + 1 > len) return nullptr;
    uint8_t compression_methods_len = data[pos];
    pos += 1;
    if (pos + compression_methods_len > len) return nullptr;
    pos += compression_methods_len;

    // Extensions Length
    if (pos + 2 > len) return nullptr;
    pos += 2;

    // Extension
    while (pos + 4 <= len) {
        uint16_t ext_type = (data[pos] << 8) | data[pos + 1];
        uint16_t ext_size = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;
        if (ext_type == 0x00) {
            if (pos + 5 > len) return nullptr;
            uint8_t name_type = data[pos + 2];
            uint16_t sni_len = (data[pos + 3] << 8) | data[pos + 4];
            if (name_type != 0) return nullptr;
            if (pos + 5 + sni_len > len) return nullptr;
            return reinterpret_cast<const char*>(&data[pos + 5]);
        }
        pos += ext_size;
    }
    return nullptr;
}

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

bool send_forward_rst(pcap_t* handle, const u_char* packet, struct libnet_ipv4_hdr* iphdr, struct libnet_tcp_hdr* tcphdr, int data_len) {
    int eth_len = LIBNET_ETH_H;
    int ip_len = iphdr->ip_hl * 4;
    int tcp_len = tcphdr->th_off * 4;
    int pkt_len = eth_len + ip_len + tcp_len;

    u_char rst_pkt[pkt_len];
    memcpy(rst_pkt, packet, pkt_len);

    struct libnet_ethernet_hdr* eth = (struct libnet_ethernet_hdr*)rst_pkt;
    memcpy(eth->ether_shost, (const uint8_t*)(uint8_t*)attacker_mac, 6);

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

    return pcap_sendpacket(handle, rst_pkt, pkt_len) == 0;
}

bool send_backward_rst(struct libnet_ipv4_hdr* iphdr, struct libnet_tcp_hdr* tcphdr, int data_len) {
    int ip_len = iphdr->ip_hl * 4;
    int tcp_len = tcphdr->th_off * 4;
    int pkt_len = ip_len + tcp_len;

    u_char pkt[pkt_len];
    memset(pkt, 0, pkt_len);

    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)pkt;
    struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)(pkt + ip_len);

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
    tcp->th_flags = TH_RST | TH_ACK;
    tcp->th_win = htons(1024);

    // pseudo-header
    u_char pseudo[12 + tcp_len];
    memcpy(pseudo, &ip->ip_src.s_addr, 4);
    memcpy(pseudo + 4, &ip->ip_dst.s_addr, 4);
    pseudo[8] = 0;
    pseudo[9] = IPPROTO_TCP;
    uint16_t tcp_size = htons(tcp_len);
    memcpy(pseudo + 10, &tcp_size, 2);
    memcpy(pseudo + 12, tcp, tcp_len);

    tcp->th_sum = 0;
    tcp->th_sum = checksum((unsigned short*)pseudo, 12 + tcp_len);

    int opt = 1;
    setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = ip->ip_dst.s_addr;

    return sendto(sd, pkt, pkt_len, 0, (sockaddr*)&dst, sizeof(dst)) >= 0;
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
    cout << "syntax : tls-block <interface> <server name>\n";
    cout << "sample : tls-block wlan0 google.com\n";
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    const char* block_server = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        cerr << "pcap_open_live failed: " << errbuf << endl;
        return -1;
    }

    if (!get_attacker_mac(dev)) {
        cerr << "Failed to get MAC address" << endl;
        return -1;
    }
    cout << "[*] Attacker MAC: " << string(attacker_mac) << endl;
    cout << "[*] TLS block start on " << dev << endl;

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res <= 0) continue;
        //printf("[*] Packet captured: %d bytes\n", header->len);

        struct ether_header* eth = (struct ether_header*)packet;
        if (ntohs(eth->ether_type) != ETHERTYPE_IP) continue;

        struct libnet_ipv4_hdr* iphdr = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);
        if (iphdr->ip_p != IPPROTO_TCP) continue;

        int iphdr_len = iphdr->ip_hl * 4;
        struct libnet_tcp_hdr* tcphdr = (struct libnet_tcp_hdr*)((uint8_t*)iphdr + iphdr_len);
        int tcphdr_len = tcphdr->th_off * 4;

        const char* data = (const char*)packet + LIBNET_ETH_H + iphdr_len + tcphdr_len;
        int data_len = ntohs(iphdr->ip_len) - iphdr_len - tcphdr_len;
        if (data_len <= static_cast<int>(sizeof(TlsRecordHeader) + sizeof(TlsHandshakeHeader))) continue;

        Key key{iphdr->ip_src.s_addr, ntohs(tcphdr->th_sport), iphdr->ip_dst.s_addr, ntohs(tcphdr->th_dport)};
        //char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        //inet_ntop(AF_INET, &iphdr->ip_src, src_ip, sizeof(src_ip));
        //inet_ntop(AF_INET, &iphdr->ip_dst, dst_ip, sizeof(dst_ip));
        //printf("[*] Connection: %s:%d -> %s:%d\n", src_ip, ntohs(tcphdr->th_sport), dst_ip, ntohs(tcphdr->th_dport));

        segment_map[key] += string(data, data_len);
        string& total_data = segment_map[key];

        const TlsRecordHeader* record = reinterpret_cast<const TlsRecordHeader*>(total_data.data());
        if (record->content_type != 0x16) continue;

        const TlsHandshakeHeader* handshake = reinterpret_cast<const TlsHandshakeHeader*>(total_data.data() + sizeof(TlsRecordHeader));
        if (handshake->handshake_type != 0x01) continue;

        const char* sni = extract_sni((const uint8_t*)total_data.data(), total_data.size());
        if (!sni) {
            printf("[-] SNI not found\n");
            continue;
        }
        printf("[*] SNI extracted: %s\n", sni);

        if (memmem(sni, strlen(sni), block_server, strlen(block_server)) != nullptr) {
            printf("[+] Blocked SNI matched: %s\n", sni);
            bool br = send_backward_rst(iphdr, tcphdr, data_len);
            bool fr = send_forward_rst(handle, packet, iphdr, tcphdr, data_len);
            if (br && fr) printf("[+] Block packets sent successfully\n");
            else printf("[-] Block packet transmission failed\n");
            segment_map.erase(key);
        }
    }

    pcap_close(handle);
    return 0;
}
