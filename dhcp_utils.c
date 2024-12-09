#include "dhcp_utils.h"

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

void set_dhcp_packet_options(unsigned char** options, uint8_t* offer_code, uint32_t* dhcp_identifier, uint32_t* subnet_mask, 
    uint32_t* default_gateway, uint32_t* broadcast_address, uint32_t* lease_time, uint32_t* dns_servers)
{
    uint8_t dhcp_cookie[4] = {0x63, 0x82, 0x53, 0x63};
    memcpy(*options, dhcp_cookie, 4);
    **options += 4;

    add_dhcp_option(*options, DHCP_TYPE, sizeof(*offer_code), offer_code);
    *options = *options + sizeof(*offer_code) + 2;

    add_dhcp_option(*options, DHCP_IDENTIFIER, sizeof(*dhcp_identifier), dhcp_identifier);
    *options = *options + sizeof(*dhcp_identifier) + 2;
    
    add_dhcp_option(*options, SUBNET_MASK, sizeof(*subnet_mask), subnet_mask);
    *options = *options + sizeof(*subnet_mask) + 2;
    
    add_dhcp_option(*options, DEFAULT_GATEWAY, sizeof(*default_gateway), default_gateway);
    *options = *options + sizeof(*default_gateway) + 2;

    add_dhcp_option(*options, BROADCAST_ADDRESS, sizeof(*broadcast_address), broadcast_address);
    *options = *options + sizeof(*broadcast_address) + 2;

    add_dhcp_option(*options, LEASE_TIME, sizeof(*lease_time), lease_time);
    *options = *options + sizeof(*lease_time) + 2;

    add_dhcp_option(*options, DNS_SERVER, 2 * sizeof(*dns_servers), dns_servers);
    *options = *options + 2 * sizeof(*dns_servers) + 2;

    **options = END_BYTE;
}

uint8_t get_message_type(unsigned char* option_ptr)
{
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
    return message_type;
}