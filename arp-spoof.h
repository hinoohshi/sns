#pragma once

#include <vector>
#include <pcap.h>
#include "mac.h"
#include "ip.h"
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
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

extern Mac myMac;
extern Ip myIp;
extern pcap_t* pcap;
extern std::vector<SpoofPair> spoofpairs;

bool getMyInfo(const char* ifname);
bool getSenderMac(pcap_t* pcap, Mac& sender_mac, Ip sender_ip);
bool sendArpSpoof(const SpoofPair& spoofpair);
void relayPacket(const u_char* packet, int packetLen);
void* infectThread(void* arg);
void detectRecoverAndReinfect(const u_char* packet, int packetLen);
