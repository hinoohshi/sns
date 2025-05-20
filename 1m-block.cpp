#include <iostream>
#include <cstdlib>
#include <cstring>
#include <string>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <unordered_set>
#include <fstream>
#include <chrono>

std::unordered_set<std::string> blocked_hosts;
int g_should_block = 0;

void dump(unsigned char* buf, int size) {
    for (int i = 0; i < size; ++i) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

void load_blocked_hosts(const char* filename) {
    std::ifstream file(filename);
    if (!file) {
        std::cerr << "Failed to open " << filename << "\n";
        exit(1);
    }

    std::string line;
    auto start = std::chrono::high_resolution_clock::now();
    size_t count = 0;

    while (std::getline(file, line)) {
        if (!line.empty()) {
            auto pos = line.find(',');
            if (pos != std::string::npos)
                line = line.substr(pos + 1);
            blocked_hosts.insert(line);
            count++;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::cout << "Loaded " << count << " blocked hosts in "
              << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count()
              << " ms\n";
}

static uint32_t print_pkt(struct nfq_data* tb) {
    uint32_t id = 0;
    struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
    }

    struct nfqnl_msg_packet_hw* hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int hlen = ntohs(hwph->hw_addrlen);
        printf("hw_src_addr=");
        for (int i = 0; i < hlen - 1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen - 1]);
    }

    uint32_t mark = nfq_get_nfmark(tb);
    if (mark) printf("mark=%u ", mark);

    uint32_t ifi = nfq_get_indev(tb);
    if (ifi) printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi) printf("outdev=%u ", ifi);

    ifi = nfq_get_physindev(tb);
    if (ifi) printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi) printf("physoutdev=%u ", ifi);

    uint32_t uid, gid;
    if (nfq_get_uid(tb, &uid)) printf("uid=%u ", uid);
    if (nfq_get_gid(tb, &gid)) printf("gid=%u ", gid);

    unsigned char* secdata;
    int ret = nfq_get_secctx(tb, &secdata);
    if (ret > 0)
        printf("secctx=\"%.*s\" ", ret, secdata);

    unsigned char* data;
    ret = nfq_get_payload(tb, &data);
    if (ret >= 0) {
        printf("payload_len=%d ", ret);
        //dump(data, ret);
    }

    if (ret < (int)sizeof(struct iphdr)) {
        printf("Too short for IP header\n");
        return id;
    }

    struct iphdr* ip = (struct iphdr*)data;
    if (ip->protocol != IPPROTO_TCP) {
        printf("Not a TCP packet\n");
        return id;
    }

    int ip_header_len = ip->ihl * 4;
    if (ret < ip_header_len + (int)sizeof(struct tcphdr)) {
        printf("Too short for TCP header\n");
        return id;
    }

    struct tcphdr* tcp = (struct tcphdr*)(data + ip_header_len);
    int tcp_header_len = tcp->doff * 4;

    if (ntohs(tcp->dest) != 80) {
        printf("Not HTTP traffic (dest port != 80)\n");
        return id;
    }

    int http_offset = ip_header_len + tcp_header_len;
    if (ret <= http_offset) {
        printf("No HTTP payload\n");
        return id;
    }

    char* http_payload = (char*)(data + http_offset);
    int http_len = ret - http_offset;

    char* host_field = (char*)memmem(http_payload, http_len, "Host:", 5);
    if (host_field) {
        char* host_start = host_field + 5;
        while (*host_start == ' ') host_start++;

        char* host_end = (char*)memchr(host_start, '\r', http_len - (host_start - http_payload));
        if (host_end) {
            int host_len = host_end - host_start;
            printf("Host: ");
            fwrite(host_start, 1, host_len, stdout);
            printf("\n");

            std::string host(host_start, host_len);
            auto search_start = std::chrono::high_resolution_clock::now();
            bool found = blocked_hosts.count(host);
            auto search_end = std::chrono::high_resolution_clock::now();

            std::cout << "Search time: "
                      << std::chrono::duration_cast<std::chrono::microseconds>(search_end - search_start).count()
                      << " us\n";

            if (found) {
                printf("Matched blocked host: %s — Marking as DROP\n", host.c_str());
                g_should_block = 1;
            }
            else {
                printf("Host not in blocked list: %s — ACCEPT\n", host.c_str());
            }
        }
    }
    else {
        printf("No Host field found\n");
    }

    fputc('\n', stdout);
    return id;
}

static int cb(struct nfq_q_handle* qh, struct nfgenmsg*, struct nfq_data* nfa, void*) {
    g_should_block = 0;
    uint32_t id = print_pkt(nfa);
    return nfq_set_verdict(qh, id, g_should_block ? NF_DROP : NF_ACCEPT, 0, nullptr);
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "syntax: %s <site list file>\n", argv[0]);
        fprintf(stderr, "sample: %s top-1m.txt\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    load_blocked_hosts(argv[1]);

    printf("opening library handle\n");
    struct nfq_handle* h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    nfq_unbind_pf(h, AF_INET);
    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    struct nfq_q_handle* qh = nfq_create_queue(h, 0, &cb, nullptr);
    if (!qh) {
        perror("nfq_create_queue failed");
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    printf("setting flags to request UID and GID\n");
    nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID);
    printf("setting flags to request security context\n");
    nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX);

    int fd = nfq_fd(h);
    char buf[4096] __attribute__((aligned));

    printf("Waiting for packets...\n");

    while (true) {
        int rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
