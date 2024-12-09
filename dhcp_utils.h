#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <err.h>
#include <memory.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>

#define DHCP_TYPE 53
#define SUBNET_MASK 1
#define DEFAULT_GATEWAY 3
#define DNS_SERVER 6
#define BROADCAST_ADDRESS 28
#define DHCP_IDENTIFIER 54
#define LEASE_TIME 51
#define REQUESTED_IP 50
#define END_BYTE 255
#define AVAILABLE 1
#define UNAVAILABLE 0

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

void print_hex(unsigned char *sir, int size);
void init_dhcp_packet(struct dhcp_packet *packet, unsigned char *ip_address);
int size_to_send(unsigned char *option_ptr);
void add_dhcp_option(unsigned char *options, uint8_t code, uint8_t length, const void *data);
uint32_t get_requested_address(unsigned char *option_ptr);
void set_dhcp_packet_options(unsigned char** options, uint8_t* offer_code, uint32_t* dhcp_identifier, uint32_t* subnet_mask, 
    uint32_t* default_gateway, uint32_t* broadcast_address, uint32_t* lease_time, uint32_t* dns_servers);
uint8_t get_message_type(unsigned char* option_ptr);