#include "configread.h"

#define DHCP_TYPE 53
#define SUBNET_MASK 1
#define DEFAULT_GATEWAY 3
#define BROADCAST_ADDRESS 28
#define DHCP_IDENTIFIER 54
#define LEASE_TIME 51
#define REQUESTED_IP 50
#define END_BYTE 255

#define MAX_IP_ADDRESS 255

struct dhcp_packet
{
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

void print_hex(unsigned char *sir, int size)
{
    for (int i = 1; i <= size; i++)
    {
        printf("%2hhx ", sir[i - 1]);
        if (i % 16 == 0)
            printf("\n");
    }
    printf("\n");
}

void init_dhcp_packet(struct dhcp_packet *packet, unsigned char *ip_address)
{
    packet->op = 2;
    packet->htype = 1;
    packet->hlen = 6;
    packet->hops = 0;
    // transaction id is set by client
    // secs is set by client
    packet->flags = htons(0x8000);
    // ciaddr is set by client
    packet->yiaddr = inet_addr(ip_address);
    packet->siaddr = inet_addr("192.168.1.2");
    packet->giaddr = inet_addr("192.168.1.1");
    // chaddr is set by client
    strcpy(packet->sname, "Test DHCP Server");
}

int size_to_send(unsigned char *option_ptr)
{
    int size = 240;
    option_ptr += 4; // skip magic cookie
    while (*option_ptr != END_BYTE)
    {
        size += 2;
        size += *(option_ptr + 1);
        option_ptr += *(option_ptr + 1);
        option_ptr += 2;
    }
    size++;
    return size;
}

void add_dhcp_option(unsigned char *options, uint8_t code, uint8_t length, const void *data)
{
    *options++ = code;
    *options++ = length;
    memcpy(options, data, length);
}

uint32_t get_requested_address(unsigned char *option_ptr)
{
    option_ptr += 4;
    while (*option_ptr != REQUESTED_IP)
    {
        // printf("Option: %d - %d\n", *option_ptr, *(option_ptr+1));
        option_ptr += *(option_ptr + 1);
        option_ptr += 2;
    }
    option_ptr += 2;
    uint32_t req_ip;
    memcpy(&req_ip, option_ptr, 4);
    return req_ip;
}

int main()
{
    struct ip_cache_entry ip1;
    strcpy(ip1.ip_address, "192.168.1.100");
    ip1.available = 1;

    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        printf("Socket creation failed");
        exit(errno);
    }

    int broadcast = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0)
    {
        printf("Failed to enable broadcast");
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

    uint8_t dhcp_cookie[4] = {0x63, 0x82, 0x53, 0x63};
    struct dhcp_packet packet;

    while (1)
    {
        memset(&packet, 0, sizeof(packet));
        recvfrom(sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)&client_addr, &client_len);
        printf("Transaction ID: %x\n", ntohl(packet.xid));

        unsigned char *option_ptr = packet.options;
        option_ptr += 4;

        uint8_t message_type;
        while (*option_ptr != 255)
        {
            if (*option_ptr == DHCP_TYPE)
            {
                message_type = *(option_ptr + 2);
                break;
            }
            option_ptr += *(option_ptr + 1) + 1;
        }
        if (message_type == 1)
        {
            printf("DHCP Discover received\n");
            ip1.available = 1; // TO BE DELETED
            init_dhcp_packet(&packet, ip1.ip_address);

            unsigned char *options = packet.options;
            memcpy(options, &dhcp_cookie, 4);
            options += 4;

            uint8_t offer_code = 2;
            add_dhcp_option(options, DHCP_TYPE, sizeof(offer_code), &offer_code);
            options = options + sizeof(offer_code) + 2;

            uint32_t dhcp_identifier = inet_addr("192.168.1.2");
            add_dhcp_option(options, DHCP_IDENTIFIER, sizeof(dhcp_identifier), &dhcp_identifier);
            options = options + sizeof(dhcp_identifier) + 2;

            uint32_t subnet_mask = inet_addr("255.255.255.0");
            add_dhcp_option(options, SUBNET_MASK, sizeof(subnet_mask), &subnet_mask);
            options = options + sizeof(subnet_mask) + 2;

            uint32_t default_gateway = inet_addr("192.168.1.1");
            add_dhcp_option(options, DEFAULT_GATEWAY, sizeof(default_gateway), &default_gateway);
            options = options + sizeof(default_gateway) + 2;

            uint32_t broadcast_address = inet_addr("192.168.1.255");
            add_dhcp_option(options, BROADCAST_ADDRESS, sizeof(broadcast_address), &broadcast_address);
            options = options + sizeof(broadcast_address) + 2;

            uint32_t lease_time = htonl(1800);
            add_dhcp_option(options, LEASE_TIME, sizeof(lease_time), &lease_time);
            options = options + sizeof(lease_time) + 2;

            *options = END_BYTE;

            memset(&client_addr, 0, client_len);
            client_addr.sin_family = AF_INET;
            client_addr.sin_addr.s_addr = INADDR_BROADCAST;
            client_addr.sin_port = htons(68);

            int actual_packet_size = size_to_send(packet.options);

            if (sendto(sockfd, &packet, actual_packet_size, 0, (struct sockaddr *)&client_addr, client_len) < 0)
            {
                printf("Failed to send DHCP Offer");
            }
            else
                printf("DHCP Offer sent to client\n");
        }
        else if (message_type == 3)
        {
            printf("DHCP Request received\n");

            uint32_t requested_ip = get_requested_address(packet.options);
            // printf("ReqIP: %x\n", requested_ip);
            if (ip1.available == 1 && requested_ip == inet_addr(ip1.ip_address))
            {
                ip1.available = 0;
                unsigned char *options = packet.options;
                memcpy(options, &dhcp_cookie, 4);
                options += 4;

                init_dhcp_packet(&packet, ip1.ip_address);

                uint8_t ack_code = 5;
                add_dhcp_option(options, DHCP_TYPE, sizeof(ack_code), &ack_code);
                options = options + sizeof(ack_code) + 2;

                uint32_t dhcp_identifier = inet_addr("192.168.1.2");
                add_dhcp_option(options, DHCP_IDENTIFIER, sizeof(dhcp_identifier), &dhcp_identifier);
                options = options + sizeof(dhcp_identifier) + 2;

                uint32_t subnet_mask = inet_addr("255.255.255.0");
                add_dhcp_option(options, SUBNET_MASK, sizeof(subnet_mask), &subnet_mask);
                options = options + sizeof(subnet_mask) + 2;

                uint32_t default_gateway = inet_addr("192.168.1.1");
                add_dhcp_option(options, DEFAULT_GATEWAY, sizeof(default_gateway), &default_gateway);
                options = options + sizeof(default_gateway) + 2;

                uint32_t broadcast_address = inet_addr("192.168.1.255");
                add_dhcp_option(options, BROADCAST_ADDRESS, sizeof(broadcast_address), &broadcast_address);
                options = options + sizeof(broadcast_address) + 2;

                uint32_t lease_time = htonl(1800);
                add_dhcp_option(options, LEASE_TIME, sizeof(lease_time), &lease_time);
                options = options + sizeof(lease_time) + 2;

                *options = END_BYTE;

                // print_hex((char*)&packet,sizeof(packet));

                memset(&client_addr, 0, client_len);
                client_addr.sin_family = AF_INET;
                client_addr.sin_addr.s_addr = INADDR_BROADCAST; // requested_ip;
                // printf("IP: %s\n",inet_ntoa(client_addr.sin_addr));
                client_addr.sin_port = htons(68);

                int actual_packet_size = size_to_send(packet.options);

                if (sendto(sockfd, &packet, actual_packet_size, 0, (struct sockaddr *)&client_addr, client_len) < 0)
                {
                    printf("Failed to send DHCP ACK\n");
                }
                else
                    printf("DHCP ACK sent to client\n");
            }
            else
                printf("IP Address is not available\n");
        }
    }

    close(sockfd);

    char *configfile = readconfigfile();

    parseConfigFile(configfile);

    int nrTotalIps;

    cacheIpAddresses(&nrTotalIps);

    struct ip_cache_entry nextAvailableIp = getNextAvailableIp(nrTotalIps);

    printf("IP: %s", nextAvailableIp.ip_address);

    return 0;
}
