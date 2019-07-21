#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

char WIP[2]; // what_is_protocol

struct eth_addr
{
        u_char eth_address_octets[6];
        // A ethernet address has 6 octets.
};

struct eth_header // Size : 14 Bytes
{
        struct eth_addr eth_destination_host; // 6 Octet
        struct eth_addr eth_source_host; // 6 Octet
        u_short eth_type; // 2 Octet
};

struct ip_header // by IP header order & Size : minimum 20 Bytes
{
        u_char version:4; // 0.5 Octet
        u_char header_len:4; // 0.5 Octet
        u_char type_of_service; // 1 Octet
        u_short total_length; // 2 Octet
        u_short identification; // 2 Octet
	u_char flags; // 0.5 Octet
        u_char frag_offset:5; // 0.5 Octet
        u_char more_fragment:1; // 0.5 Octet
        u_char dont_fragment:1; // 0.5 Octet
        u_char reserved_zero:1; // 0.5 Octet
        u_char time_to_live; // 1 Octet
        u_char protocol; // 1 Octet
        u_short header_checksum; // 2 Octet
        struct in_addr source_address; // 4 Octet
        struct in_addr destination_address; // 4 Octet
};

struct tcp_header // by TCP header order & Size : minimum 20 Bytes
{
        u_short source_port; // 2 Octet
        u_short dest_port; // 2 Octet
        u_int sequence; // 4 Octet
        u_int acknowledge; // 4 Octet
        u_char header_length:1; // 1 Octet
        u_char reserved_part:3; // 1 Octet
        u_char data_offset:4; // 0.5 Octet
        u_char fin:1;
        u_char syn:1;
        u_char rst:1;
        u_char psh:1;
        u_char ack:1;
        u_char urg:1;
        u_char ece:1;
        u_char cwr:1; // total 1.5 Octet
        u_short window; // 2 Octet
        u_short checksum; // 2 Octet
        u_short urgent_pointer; // 2 Octet
};

struct udp_header
{
	u_short source_port; // 2 Octet
	u_short dest_port; // 2 Octet
	u_short length; // 2 Octet
	u_short checksum; // 2 Octet
};

///////////////////////////////////////////////////////////

uint8_t Print_Eth(const u_char* Packet_DATA){
    struct eth_header* EH = (struct eth_header*)(Packet_DATA);
    uint8_t EH_length = (uint8_t)(sizeof(EH));
    u_short ethernet_type;
    ethernet_type = ntohs(EH->eth_type);

    if(ethernet_type != 0x0800){
        printf("Ethernet type is not IP\n");
        return 0;
    } // IP CHECK

    printf("[Source] <MAC> Address : %02x:%02x:%02x:%02x:%02x:%02x:\n",
           EH->eth_source_host.eth_address_octets[0],
            EH->eth_source_host.eth_address_octets[1],
             EH->eth_source_host.eth_address_octets[2],
              EH->eth_source_host.eth_address_octets[3],
               EH->eth_source_host.eth_address_octets[4],
                EH->eth_source_host.eth_address_octets[5]);

    printf("[Destination] <MAC> Address : %02x:%02x:%02x:%02x:%02x:%02x:\n",
           EH->eth_destination_host.eth_address_octets[0],
            EH->eth_destination_host.eth_address_octets[1],
             EH->eth_destination_host.eth_address_octets[2],
              EH->eth_destination_host.eth_address_octets[3],
               EH->eth_destination_host.eth_address_octets[4],
                EH->eth_destination_host.eth_address_octets[5]);
    return EH_length;
}

char* Print_IP(const u_char* Packet_DATA){
    struct ip_header* IH = (struct ip_header*)(Packet_DATA);

    // IP Check
    if(IH->header_len == 0) return 0;
    if(IH->version < 4 && IH->version > 9) return 0;
    // 4 : IP
    // 5 : ST
    // 6 : SIP, SIPP, IPv6
    // 7 : TP/IX
    // 8 : PIP
    // 9 : TUBA

    //printf("TTL : %x\n", IH->time_to_live);
    //printf("protocol : %x\n", IH->protocol);

    sprintf(WIP, "%x", IH->protocol);
    //printf("WIP : %s\n", WIP);

    printf("[Source] <IP> Address : %s\n", inet_ntoa(IH->source_address));
    printf("[Destination] <IP> Address : %s\n", inet_ntoa(IH->destination_address));

    return WIP;
}

int print_TCP(const u_char* Packet_DATA){
    struct tcp_header* TH = (struct tcp_header*)(Packet_DATA);

    // TCP check
    if(TH->data_offset < 4) return 0;

    char* sp = (char*)malloc(sizeof(TH->source_port));
    sprintf(sp, "%d", ntohs(TH->source_port));
    char* dp = (char*)malloc(sizeof(TH->dest_port));
    sprintf(dp, "%d", ntohs(TH->dest_port));

    //printf("sp : %s\n", sp);
    //printf("dp : %s\n", dp);

    if((!strcmp(sp, "443")) || (!strcmp(dp, "443"))){
        printf("TCP SSL(HTTPS) protocol\n");
    }
    else if((!strcmp(sp, "25")) || (!strcmp(dp, "25"))){
        printf("TCP SMTP protocol\n");
    }
    else if((!strcmp(sp, "53")) || (!strcmp(dp, "53"))){
        printf("TCP DNS protocol\n");
    }
    else if((!strcmp(sp, "80")) || (!strcmp(dp, "80"))){
        printf("TCP HTTP protocol\n");
    }
    else if((!strcmp(sp, "22")) || (!strcmp(dp, "22"))){
        printf("TCP SSH protocol\n");
    }
    else if((!strcmp(sp, "23")) || (!strcmp(dp, "23"))){
        printf("TCP Telnet protocol\n");
    }
    else if((!strcmp(sp, "111")) || (!strcmp(dp, "111"))){
        printf("TCP RPC protocol\n");
    }

    printf("[Source] <Port> Number : %d\n", ntohs(TH->source_port));
    printf("[Destination] <Port> Number : %d\n", ntohs(TH->dest_port));

    return ((TH->data_offset) * 4);
}


int print_UDP(const u_char* Packet_DATA){
    struct udp_header* UH = (struct udp_header*)(Packet_DATA);

    char* sp = (char*)malloc(sizeof(UH->source_port));
    sprintf(sp, "%d", ntohs(UH->source_port));
    char* dp = (char*)malloc(sizeof(UH->dest_port));
    sprintf(dp, "%d", ntohs(UH->dest_port));

    //printf("sp : %s\n", sp);
    //printf("dp : %s\n", dp);

    if((!strcmp(sp, "80")) || (!strcmp(dp, "80"))){
        printf("UDP HTTP protocol\n");
    }
    else if((!strcmp(sp, "161")) || (!strcmp(dp, "161"))){
        printf("UDP SNMP protocol\n");
    }
    else if((!strcmp(sp, "111")) || (!strcmp(dp, "111"))){
        printf("UDP RPC protocol\n");
    }

    printf("[Source] <Port> Number : %d\n", ntohs(UH->source_port));
    printf("[Destination] <Port> Number : %d\n", ntohs(UH->dest_port));

    return (UH->length);
}

void print_Data(const u_char* Packet_DATA){
    for(int i = 0; i < 10; i++) printf("%c", Packet_DATA[i]);
    printf("\n");
}


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    printf("########################\n\n");
    printf("-- %u Bytes captured --\n\n", header->caplen);

    printf("-------_Ethernet_-------\n");
    uint8_t tmp = 0; // Ethernet header size
    tmp = Print_Eth(packet);
    //printf("packet : %d\n", tmp);
    if(tmp > 14) break;
    printf("\n");

    printf("----------_IP_----------\n");
    packet += 14;
    char* tmp2; // IP protocol type
    int WIP = 0; // protocol's header size
    tmp2 = Print_IP(packet);
    printf("\n");

    //printf("tmp2 = %s\n", tmp2);
    if(!strcmp(tmp2, "6")){ // TCP header : 20 Bytes
        WIP = 20;
    }
    else if(!strcmp(tmp2, "11") || !strcmp(tmp2, "1")){
        WIP = 8; // UDP header & ICMP header : 8 Bytes
    }
    else if(!strcmp(tmp2, "84")){
        WIP = 4; // SCTP header : 4Bytes
    }

    if(!strcmp(tmp2, "6"))
        printf("---------_TCP_---------\n");
    else if(!strcmp(tmp2, "11"))
        printf("---------_UDP_---------\n");
    else
        printf("--------_Protocol_--------\n");

    packet += 20;
    if(!strcmp(tmp2, "6"))
        print_TCP(packet);
    else if(!strcmp(tmp2, "11"))
        print_UDP(packet);
    else
        printf("No Header Data here for this protocol!\n");
    //printf("WIP : %d\n", WIP);
    printf("\n");

    printf("---------_DATA_---------\n");
    packet += WIP;
    if((!strcmp(tmp2, "6")) || (!strcmp(tmp2, "11")))
        print_Data(packet);
    else
        printf("No Protocol Data here!\n");
    printf("\n");

    printf("########################\n");
    printf("\n\n");
  }

  pcap_close(handle);
  return 0;
}
