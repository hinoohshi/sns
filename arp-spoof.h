#pragma once

#include <pcap.h>
#include <vector>
#include <string>
#include "mac.h"
#include "ip.h"
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

struct SpoofPair {
    Ip senderIp;
    Ip targetIp;
    Mac senderMac;
    Mac targetMac;
};

struct FlowContext {
    SpoofPair spoofpair;
    pcap_t* pcap;
};

extern Mac myMac;
extern Ip myIp;
extern pcap_t* pcap;
extern std::vector<SpoofPair> spoofpairs;

bool getMyInfo(const char* dev);
bool getMac(pcap_t* pcap, Mac& mac, Ip ip);
bool sendArpSpoof(const SpoofPair& pair);
void* spoofThread(void* arg);
void* relayThread(void* arg);
