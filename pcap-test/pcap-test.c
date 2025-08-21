#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void print_ethernet_header(struct libnet_ethernet_hdr* eth) {
    printf("Ethernet Header: ");
    printf("%02x:%02x:%02x:%02x:%02x:%02x -> ",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("%02x:%02x:%02x:%02x:%02x:%02x, ",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
}

void print_ip_header(struct libnet_ipv4_hdr* ip) {
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->ip_dst), dst_ip, INET_ADDRSTRLEN);
    printf("IP Header: ");
    printf("%s -> ", src_ip);
    printf("%s\n", dst_ip);
}

void print_tcp_header(struct libnet_tcp_hdr* tcp) {
    printf("TCP Header: ");
    printf("%d -> ", ntohs(tcp->th_sport));
    printf("%d\n", ntohs(tcp->th_dport));
}

void print_payload(const u_char* payload, int payload_len) {
    if (payload_len == 0) {
        printf("-\n");
    }
    else {
        printf("Payload (%d bytes): ", payload_len > 20 ? 20 : payload_len);
        for (int i = 0; i < payload_len && i < 20; i++) {
            printf("%02x|", payload[i]);
        }
        printf("\b \n");
    }
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        printf("\n%u bytes captured\n", header->caplen);

        struct libnet_ethernet_hdr* ethdr;
        struct libnet_ipv4_hdr* iphdr;
        struct libnet_tcp_hdr* tcphdr;
        int ethernet_header_len = 14;

        ethdr = (struct libnet_ethernet_hdr *)(packet);
        if (ntohs(ethdr->ether_type) != ETHERTYPE_IP) continue;

        iphdr  = (struct libnet_ipv4_hdr *)(packet + ethernet_header_len);
        if (iphdr->ip_p != IPPROTO_TCP) continue;

        int ip_header_len = iphdr->ip_hl * 4;
        tcphdr = (struct libnet_tcp_hdr *)(packet + ethernet_header_len + ip_header_len);

        int tcp_header_len = tcphdr->th_off * 4;
        int total_header_size = ethernet_header_len + ip_header_len + tcp_header_len;
        int payload_len = header->caplen - total_header_size;
        const u_char *payload = packet + total_header_size;

        print_ethernet_header(ethdr);
        print_ip_header(iphdr);
        print_tcp_header(tcphdr);
        print_payload(payload, payload_len);
    }

    pcap_close(pcap);
}
