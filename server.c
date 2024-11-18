#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>

struct dhcp_packet {
    uint8_t op;                   
    uint8_t htype;                
    uint8_t hlen;                 
    uint8_t hops;                 
    uint32_t xid;                 
    uint16_t secs;                
    uint16_t flags;               
    uint32_t ciaddr;              
    uint32_t yiaddr;              
    uint32_t siaddr;              
    uint32_t giaddr;              
    unsigned char chaddr[16];     
    char sname[64];               
    char file[128];               
    unsigned char options[312];   
};


const char available_ip[] = "192.168.1.100";
int ip_assigned = 0;  


void add_dhcp_option(unsigned char *options, uint8_t code, uint8_t length, const void *data) {
    *options++ = code;
    *options++ = length;
    memcpy(options, data, length);
}

int main() 
{    
    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
    {
        printf("Socket creation failed");
        exit(errno);
    }

    struct sockaddr_in server_addr;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(67); 

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) 
    {
        printf("Bind failed");
        close(sockfd);
        exit(errno);
    }
    
    printf("DHCP Server is running...\n");

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    struct dhcp_packet packet;

    while (1) 
    {
        memset(&packet, 0, sizeof(packet));
        recvfrom(sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)&client_addr, &client_len);
        printf("%x\n",packet.xid);
        unsigned char *option_ptr = packet.options;
        uint8_t message_type;
        
        while (*option_ptr != 255) 
        {  
            if (*option_ptr == 53) 
            {  
                message_type = *(option_ptr + 2); 
                break;
            }
            option_ptr += *(option_ptr + 1) + 1; 
        }
        printf("ok");
        if (message_type == 1) 
        { 
            printf("DHCP Discover received\n");
            
            packet.op = 2; 
            packet.yiaddr = inet_addr(available_ip); 
            packet.siaddr = inet_addr("192.168.1.1");
             
            unsigned char *options = packet.options;
            uint8_t offer_code = 2;
            add_dhcp_option(options, 53, 1, &offer_code); 
            options += 3;
            uint32_t subnet_mask = inet_addr("255.255.255.0");
            add_dhcp_option(options, 1, 4, &subnet_mask); 
            options += 6;
            uint32_t default_gateway = inet_addr("192.168.1.1");
            add_dhcp_option(options, 3, 4, &default_gateway); 
            options += 6;
            uint32_t lease_time = htonl(3600);
            add_dhcp_option(options, 51, 4, &lease_time); 
            options += 6;
            *options = 255; 

            
            if (sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)&client_addr, client_len) < 0)
            {
                printf("Failed to send DHCP Offer");
            }
            else 
                printf("DHCP Offer sent to client\n");
        }
        else if (message_type == 3) 
        { 
            printf("DHCP Request received\n");
            
            if (!ip_assigned || packet.yiaddr == inet_addr(available_ip)) 
            {
                ip_assigned = 1; 

                packet.op = 2; 
                packet.yiaddr = inet_addr(available_ip); 
                packet.siaddr = inet_addr("192.168.1.1"); 
                
                
                unsigned char *options = packet.options;
                add_dhcp_option(options, 53, 1, (uint8_t[]){5}); 
                options += 3;
                add_dhcp_option(options, 1, 4, (uint32_t[]){inet_addr("255.255.255.0")}); 
                options += 6;
                add_dhcp_option(options, 3, 4, (uint32_t[]){inet_addr("192.168.1.1")}); 
                options += 6;
                add_dhcp_option(options, 51, 4, (uint32_t[]){htonl(3600)}); 
                options += 6;
                *options = 255; 

                
                if (sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)&client_addr, client_len) < 0) {
                    printf("Failed to send DHCP ACK");
                } else 
                    printf("DHCP ACK sent to client\n");
                
            } 
            else 
            {
                printf("Requested IP is already assigned\n");
            }
        }
    }
    
    close(sockfd);
    return 0;
}
