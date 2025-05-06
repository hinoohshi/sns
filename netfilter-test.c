#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

int g_should_block = 0;

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

/* returns packet id */
static uint32_t print_pkt (struct nfq_data *tb, const char *block_host)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	uint32_t mark, ifi, uid, gid;
	int ret;
	unsigned char *data, *secdata;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	if (nfq_get_uid(tb, &uid))
		printf("uid=%u ", uid);

	if (nfq_get_gid(tb, &gid))
		printf("gid=%u ", gid);

	ret = nfq_get_secctx(tb, &secdata);
	if (ret > 0)
		printf("secctx=\"%.*s\" ", ret, secdata);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
        printf("payload_len=%d ", ret);
        dump(data, ret);

        if (ret < sizeof(struct iphdr)) {
            printf("Too short for IP header\n");
            return id;
        }

        /* IP parsing */
        struct iphdr *ip = (struct iphdr *)data;
        if (ip->protocol != IPPROTO_TCP) {
            printf("Not a TCP packet\n");
            return id;
        }

        int ip_header_len = ip->ihl * 4;
        if (ret < ip_header_len + sizeof(struct tcphdr)) {
            printf("Too short for TCP header\n");
            return id;
        }

        /* TCP parsing */
        struct tcphdr *tcp = (struct tcphdr *)(data + ip_header_len);
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

        /* HTTP parsing */
        char *http_payload = (char *)(data + http_offset);
        int http_len = ret - http_offset;
        char *host_field = memmem(http_payload, http_len, "Host:", 5);
        if (host_field) {
            char *host_start = host_field + 5;
            while (*host_start == ' ') host_start++;

            char *host_end = memchr(host_start, '\r', http_len - (host_start - http_payload));
            if (host_end) {
                int host_len = host_end - host_start;
                printf("Host: ");
                fwrite(host_start, 1, host_len, stdout);
                printf("\n");

                if (strlen(block_host) == host_len &&
                    strncmp(host_start, block_host, host_len) == 0) {
                    printf("Matched blocked host: %s — Marking as DROP\n", block_host);
                    g_should_block = 1;
                }
            }
        }
        else {
            printf("No Host field found\n");
        }

	fputc('\n', stdout);

	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
    const char *block_host = (const char *)data;
    g_should_block = 0;   // initialize

    uint32_t id = print_pkt(nfa, block_host);
    return nfq_set_verdict(qh, id, g_should_block ? NF_DROP : NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	uint32_t queue = 0;
	char buf[4096] __attribute__ ((aligned));

    if (argc != 2) {
        fprintf(stderr, "syntax: %s <host>\n", argv[0]);
        fprintf(stderr, "sample: %s test.gilgil.net\n", argv[0]);
        exit(EXIT_FAILURE);
	}

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '%d'\n", queue);
    qh = nfq_create_queue(h, queue, &cb, argv[1]);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	printf("setting flags to request UID and GID\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve process UID/GID.\n");
	}

	printf("setting flags to request security context\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve security context.\n");
	}

	printf("Waiting for packets...\n");

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
