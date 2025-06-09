#pragma once
#include <iostream>
#include <map>
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

#pragma pack(push, 1)

struct TlsRecordHeader {
    uint8_t content_type;   // 0x16 = Handshake
    uint16_t version;       // TLS version (e.g. 0x0301 ~ 0x0304)
    uint16_t length;        // Length of TLS payload
};

struct TlsHandshakeHeader {
    uint8_t handshake_type; // 0x01 = Client Hello
    uint8_t length[3];      // Length of handshake payload (3 bytes)
};

#pragma pack(pop)

struct Key {
    uint32_t sip;
    uint16_t sport;
    uint32_t dip;
    uint16_t dport;

    bool operator<(const Key& r) const {
        return std::tie(sip, sport, dip, dport) < std::tie(r.sip, r.sport, r.dip, r.dport);
    }
};
