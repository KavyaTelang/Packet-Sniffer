#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <signal.h>

#define BUFFER_SIZE 65536

// Statistics
int total_packets = 0;
int tcp_count = 0;
int udp_count = 0;
int icmp_count = 0;
int other_count = 0;

volatile sig_atomic_t keep_running = 1;

void signal_handler(int sig) {
    keep_running = 0;
}

void print_stats() {
    printf("\n\n========== PACKET STATISTICS ==========\n");
    printf("Total Packets Captured: %d\n", total_packets);
    printf("TCP Packets:            %d (%.1f%%)\n", tcp_count, 
           total_packets ? (tcp_count * 100.0 / total_packets) : 0);
    printf("UDP Packets:            %d (%.1f%%)\n", udp_count,
           total_packets ? (udp_count * 100.0 / total_packets) : 0);
    printf("ICMP Packets:           %d (%.1f%%)\n", icmp_count,
           total_packets ? (icmp_count * 100.0 / total_packets) : 0);
    printf("Other Packets:          %d (%.1f%%)\n", other_count,
           total_packets ? (other_count * 100.0 / total_packets) : 0);
    printf("=======================================\n\n");
}

void print_ethernet_header(unsigned char *buffer) {
    struct ethhdr *eth = (struct ethhdr *)buffer;
    
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║                    ETHERNET HEADER                         ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║ Source MAC:      %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("║ Dest MAC:        %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("║ Protocol:        0x%.4X\n", ntohs(eth->h_proto));
    printf("╚════════════════════════════════════════════════════════════╝\n");
}

void print_ip_header(unsigned char *buffer) {
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct sockaddr_in source, dest;
    
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║                       IP HEADER                            ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║ Version:         %d\n", (unsigned int)iph->version);
    printf("║ Header Length:   %d bytes\n", ((unsigned int)(iph->ihl)) * 4);
    printf("║ Type of Service: %d\n", (unsigned int)iph->tos);
    printf("║ Total Length:    %d bytes\n", ntohs(iph->tot_len));
    printf("║ Identification:  %d\n", ntohs(iph->id));
    printf("║ TTL:             %d\n", (unsigned int)iph->ttl);
    printf("║ Protocol:        %d\n", (unsigned int)iph->protocol);
    printf("║ Checksum:        0x%.4X\n", ntohs(iph->check));
    printf("║ Source IP:       %s\n", inet_ntoa(source.sin_addr));
    printf("║ Dest IP:         %s\n", inet_ntoa(dest.sin_addr));
    printf("╚════════════════════════════════════════════════════════════╝\n");
}

void print_tcp_header(unsigned char *buffer, int size) {
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
    struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));
    
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║                      TCP HEADER                            ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║ Source Port:     %u\n", ntohs(tcph->source));
    printf("║ Dest Port:       %u\n", ntohs(tcph->dest));
    printf("║ Sequence:        %u\n", ntohl(tcph->seq));
    printf("║ Ack Sequence:    %u\n", ntohl(tcph->ack_seq));
    printf("║ Header Length:   %d bytes\n", (unsigned int)tcph->doff * 4);
    printf("║ Flags:           ");
    if(tcph->urg) printf("URG ");
    if(tcph->ack) printf("ACK ");
    if(tcph->psh) printf("PSH ");
    if(tcph->rst) printf("RST ");
    if(tcph->syn) printf("SYN ");
    if(tcph->fin) printf("FIN ");
    printf("\n║ Window Size:     %d\n", ntohs(tcph->window));
    printf("║ Checksum:        0x%.4X\n", ntohs(tcph->check));
    printf("║ Urgent Pointer:  %d\n", tcph->urg_ptr);
    printf("╚════════════════════════════════════════════════════════════╝\n");
}

void print_udp_header(unsigned char *buffer, int size) {
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
    struct udphdr *udph = (struct udphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));
    
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║                      UDP HEADER                            ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║ Source Port:     %u\n", ntohs(udph->source));
    printf("║ Dest Port:       %u\n", ntohs(udph->dest));
    printf("║ Length:          %d bytes\n", ntohs(udph->len));
    printf("║ Checksum:        0x%.4X\n", ntohs(udph->check));
    printf("╚════════════════════════════════════════════════════════════╝\n");
}

void print_icmp_header(unsigned char *buffer, int size) {
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl * 4;
    struct icmphdr *icmph = (struct icmphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));
    
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║                     ICMP HEADER                            ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║ Type:            %d\n", (unsigned int)(icmph->type));
    printf("║ Code:            %d\n", (unsigned int)(icmph->code));
    printf("║ Checksum:        0x%.4X\n", ntohs(icmph->checksum));
    printf("╚════════════════════════════════════════════════════════════╝\n");
}

void print_payload(unsigned char *buffer, int size, int offset) {
    unsigned char *data = buffer + offset;
    int data_size = size - offset;
    
    if(data_size <= 0) return;
    
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║                      PAYLOAD DATA                          ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    
    // Print first 64 bytes of payload
    int print_size = data_size > 64 ? 64 : data_size;
    for(int i = 0; i < print_size; i++) {
        if(i % 16 == 0) printf("║ ");
        printf("%02X ", data[i]);
        if((i + 1) % 16 == 0) printf("\n");
    }
    if(print_size % 16 != 0) printf("\n");
    
    if(data_size > 64) {
        printf("║ ... (%d more bytes)\n", data_size - 64);
    }
    printf("╚════════════════════════════════════════════════════════════╝\n");
}

void process_packet(unsigned char *buffer, int size) {
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    
    total_packets++;
    
    printf("\n\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("                    PACKET #%d (Size: %d bytes)\n", total_packets, size);
    printf("═══════════════════════════════════════════════════════════════\n");
    
    print_ethernet_header(buffer);
    print_ip_header(buffer);
    
    switch (iph->protocol) {
        case 6: // TCP
            tcp_count++;
            print_tcp_header(buffer, size);
            printf("\n[Protocol: TCP]\n");
            break;
            
        case 17: // UDP
            udp_count++;
            print_udp_header(buffer, size);
            printf("\n[Protocol: UDP]\n");
            break;
            
        case 1: // ICMP
            icmp_count++;
            print_icmp_header(buffer, size);
            printf("\n[Protocol: ICMP]\n");
            break;
            
        default:
            other_count++;
            printf("\n[Protocol: Other (%d)]\n", iph->protocol);
            break;
    }
    
    // Uncomment to see payload data
    // int header_size = sizeof(struct ethhdr) + iph->ihl * 4;
    // print_payload(buffer, size, header_size);
    
    printf("\n");
}

int main() {
    int sock_raw;
    unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE);
    struct sockaddr saddr;
    socklen_t saddr_len = sizeof(saddr);
    
    signal(SIGINT, signal_handler);
    
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║           NETWORK PACKET SNIFFER - STARTING              ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");
    printf("\nPress Ctrl+C to stop capturing and see statistics...\n\n");
    
    // Create raw socket
    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    
    if (sock_raw < 0) {
        perror("Socket creation failed");
        printf("\nNote: This program requires root privileges!\n");
        printf("Run with: sudo ./sniffer\n\n");
        return 1;
    }
    
    printf("✓ Raw socket created successfully\n");
    printf("✓ Capturing packets on all interfaces...\n\n");
    
    while (keep_running) {
        int data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, &saddr, &saddr_len);
        
        if (data_size < 0) {
            if (keep_running) {
                perror("Recvfrom error");
            }
            break;
        }
        
        process_packet(buffer, data_size);
    }
    
    close(sock_raw);
    free(buffer);
    
    print_stats();
    
    printf("\nPacket capture stopped.\n\n");
    
    return 0;
}
