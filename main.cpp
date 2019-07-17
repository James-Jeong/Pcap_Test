#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

void Print_Eth(const u_char* Packet_DATA){
    struct eth_header* EH = (struct eth_header*)(Packet_DATA);
    u_short ethernet_type;
    ethernet_type = ntohs(EH->eth_type);

    if(ethernet_type != 0x0800){
        printf("Ethernet type is not IP\n");
        return ;
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
}

int Print_IP(const u_char* Packet_DATA){
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


    printf("[Source] <IP> Address : %s\n", inet_ntoa(IH->source_address));
    printf("[Destination] <IP> Address : %s\n", inet_ntoa(IH->destination_address));

    return ((IH->header_len) * 4);
}

int print_TCP(const u_char* Packet_DATA){
    struct tcp_header* TH = (struct tcp_header*)(Packet_DATA);

    // TCP check
    if(TH->data_offset < 4) return 0;

    printf("[Source] <Port> Number : %d\n", ntohs(TH->source_port));
    printf("[Destination] <Port> Number : %d\n", ntohs(TH->dest_port));

    return ((TH->data_offset) * 4);
}

void print_Data(const u_char* Packet_DATA){
    int n = sizeof (Packet_DATA);
    if(n > 10) return ;
    for(int i = 0; i < n; i++) printf("%c", Packet_DATA[i]);
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

  int where = 0;
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
    Print_Eth(packet);
    printf("\n");

    printf("----------_IP_----------\n");
    packet += 14;
    where = Print_IP(packet);
    printf("\n");

    printf("----------_TCP_---------\n");
    packet += where;
    where = print_TCP(packet);
    printf("\n");

    printf("---------_DATA_---------\n");
    packet += where;
    print_Data(packet);
    printf("\n");

    printf("########################\n");
    printf("\n\n");
  }

  pcap_close(handle);
  return 0;
}
