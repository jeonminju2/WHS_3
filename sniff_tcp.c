#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <ctype.h>

#define ETHERNET_HEADER_LEN 14

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + ETHERNET_HEADER_LEN);
    int ip_header_len = ip_header->ip_hl * 4;

    struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETHERNET_HEADER_LEN + ip_header_len);
    int tcp_header_len = tcp_header->th_off * 4;

    const u_char *payload = packet + ETHERNET_HEADER_LEN + ip_header_len + tcp_header_len;
    int payload_len = header->len - (ETHERNET_HEADER_LEN + ip_header_len + tcp_header_len);

    printf("\n=== PACKET ===\n");

    // Ethernet
    printf("Ethernet Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
    printf("Ethernet Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);

    // IP
    printf("IP Src: %s\n", inet_ntoa(ip_header->ip_src));
    printf("IP Dst: %s\n", inet_ntoa(ip_header->ip_dst));

    // TCP
    printf("TCP Src Port: %d\n", ntohs(tcp_header->th_sport));
    printf("TCP Dst Port: %d\n", ntohs(tcp_header->th_dport));

    // Payload
    if (payload_len > 0) {
        printf("Payload (%d bytes): ", payload_len);
        for (int i = 0; i < payload_len && i < 32; i++) {
            printf("%c", isprint(payload[i]) ? payload[i] : '.');
        }
        printf("\n");
    } else {
        printf("Payload (0 bytes)\n");
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf); // 인터페이스 이름 확인 필요
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 2;
    }

    pcap_loop(handle, 0, got_packet, NULL);
    pcap_close(handle);
    return 0;
}
