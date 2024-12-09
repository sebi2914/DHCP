#define CONFIGFILE "dhcpconfig"
#define LEASETIME 1800
#define AVAILABLE 1
#define UNAVAILABLE 0

#define _GNU_SOURCE

#include "configread.h"

char network[16], mask[16], gateway[16], dns1[16], dns2[16], domain[16], broadcastIP[16], adresaIPServer[16];

struct ip_cache_entry *ips = NULL;

void errExit(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

char *readconfigfile()
{
    int rd;
    int fd = open(CONFIGFILE, O_RDONLY);
    if (fd == -1)
        errExit("open config");

    char *buff = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (buff == (void *)(-1))
        errExit("mmap");

    rd = close(fd);
    if (rd == -1)
        errExit("close");

    return buff;
}

int getType(char *buff)
{
    if (strcmp(buff, "network") == 0)
        return 1;
    if (strcmp(buff, "subnet-mask") == 0)
        return 2;
    if (strcmp(buff, "gateway") == 0)
        return 3;
    if (strcmp(buff, "dns1") == 0)
        return 4;
    if (strcmp(buff, "dns2") == 0)
        return 5;
    if (strcmp(buff, "domain-name") == 0)
        return 6;
}

void parseConfigFile(char *buff)
{
    char *p = strtok(buff, " \n"), *b;

    while (p)
    {
        b = p;
        p = strtok(NULL, " \n");
        int a = getType(b);
        switch (a)
        {
        case 1:
            strcpy(network, p);
            break;
        case 2:
            strcpy(mask, p);
            break;
        case 3:
            strcpy(gateway, p);
            break;
        case 4:
            strcpy(dns1, p);
            break;
        case 5:
            strcpy(dns2, p);
            break;
        case 6:
            strcpy(domain, p);
            break;
        default:
            break;
        }
    }
}

uint32_t calculate_ip_addresses(const char *subnet_mask)
{
    uint32_t mask = 0;
    int prefix = 0;

    if (inet_pton(AF_INET, subnet_mask, &mask) != 1)
    {
        return 0;
    }

    mask = ntohl(mask);

    for (int i = 0; i < 32; i++)
    {
        if (mask & (1 << (31 - i)))
        {
            prefix++;
        }
        else
        {
            break;
        }
    }

    uint32_t total_addresses = (1U << (32 - prefix));

    if (prefix < 31)
    {
        return total_addresses - 2;
    }

    return total_addresses;
}

struct ip_cache_entry *cacheIpAddresses(int *n)
{
    int total_addresses = calculate_ip_addresses(mask);
    ips = malloc(sizeof(struct ip_cache_entry) * total_addresses);
    if (ips == NULL)
        errExit("malloc");

    *n = total_addresses;

    struct in_addr subnet_addr;
    inet_pton(AF_INET, network, &subnet_addr);

    uint32_t base_ip = ntohl(subnet_addr.s_addr);

    struct in_addr mask_addr, broadcast_addr;
    inet_pton(AF_INET, mask, &mask_addr);

    uint32_t mask_val = ntohl(mask_addr.s_addr);
    uint32_t broadcast_ip = base_ip | (~mask_val);

    broadcast_addr.s_addr = htonl(broadcast_ip);

    inet_ntop(AF_INET, &broadcast_addr, broadcastIP, INET_ADDRSTRLEN);

    printf("Broadcast address: %s\n", broadcastIP);

    for (int i = 0; i < total_addresses - 1; i++)
    {
        ips[i].available = AVAILABLE;
        ips[i].lease_time = LEASETIME;
        memset(ips[i].mac_addr,0,6);
        uint32_t current_ip = base_ip + 2 + i;

        struct in_addr ip;
        ip.s_addr = htonl(current_ip);

        inet_ntop(AF_INET, &ip, (char *)ips[i].ip_address, sizeof(ips[i].ip_address));
    }

    setUnavailable(total_addresses);

    return ips;
}

void setUnavailable(int totalAddresses)
{
    int sock;
    struct ifreq ifr;
    char ip[INET_ADDRSTRLEN];

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        errExit("socket");

    strncpy(ifr.ifr_name, "ens33", IFNAMSIZ - 1); // Exemplu: ens33. interfata de retea, se modifica pentru adresa altei interfete

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
    {
        errExit("ioctl");
        close(sock);
    }

    close(sock);

    struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
    inet_ntop(AF_INET, &ipaddr->sin_addr, ip, sizeof(ip));

    printf("IP Address of the server: %s\n", ip);

    for (int i = 0; i < totalAddresses; i++)
    {
        if (strcmp(ips[i].ip_address, ip) == 0)
        {
            ips[i].available = UNAVAILABLE;
            strcpy(adresaIPServer, ips[i].ip_address);
        }
    }
}

struct ip_cache_entry getNextAvailableIp(int n)
{
    int c = 0;
    for (int i = 0; i < n; i++)
    {
        if (ips[i].available == AVAILABLE)
        {
            ips[i].available = UNAVAILABLE;
            return ips[i];
        }
        else
            c++;
    }
    if (c == n)
        errExit("No more available IPs!");
    errExit("Next available IP");
}

int check_mac_addr(uint8_t cache_addr[6], unsigned char incoming_addr[16])
{
    for(int i=0;i<6;i++)
        if(cache_addr[i] != incoming_addr[i])
            return 0;
    return 1;
}

int check_mac_in_cache(unsigned char *client_mac, int cache_size)
{
    for(int i=0;i<cache_size;i++)
    {
        if(check_mac_addr(ips[i].mac_addr,client_mac))
            {
                if(ips[i].available == UNAVAILABLE)
                    return 1;
                return 0;
            }
    }
    return 0;
}

void set_mac_to_addr(unsigned char *mac_addr, unsigned char *ip_addr, int cache_size)
{
    for(int i=0;i<cache_size;i++)
    {
        if(strcmp(ips[i].ip_address,ip_addr) == 0)
        {
            memcpy(ips[i].mac_addr, mac_addr, 6);
            return;
        }
    }
}
