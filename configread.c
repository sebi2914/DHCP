#define CONFIGFILE "dhcpconfig"
#define LEASETIME 1800
#define AVAILABLE 1
#define UNAVAILABLE 0

#define WRITE_HEAD 1
#define READ_HEAD 0

#define _GNU_SOURCE

#include "configread.h"

char network[16], mask[16], gateway[16], dns1[16], dns2[16], domain[16], broadcastIP[16], adresaIPServer[16];
uint16_t leasing_time = LEASETIME;

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
        ips[i].lease_time = 0;
        memset(ips[i].mac_addr, 0, 6); // initializare MAC cu 0
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
    char buffer[16];

    FILE *cmd = popen("ifconfig | egrep -o \"inet\\s+([0-9]{1,3}\\.){3}[0-9]{1,3}\" | egrep -v \"127\\.\" | head -n 1 | awk '{print $2}'", "r");
    if (cmd == NULL)
    {
        perror("popen failed");
        exit(EXIT_FAILURE);
    }

    if (fgets(buffer, sizeof(buffer), cmd) != NULL)
    {
        buffer[strcspn(buffer, "\n")] = '\0';
        printf("IP Address: %s\n", buffer);

        for (int i = 0; i < totalAddresses; i++)
        {
            if (strcmp(ips[i].ip_address, buffer) == 0)
            {
                ips[i].available = UNAVAILABLE;
                strcpy(adresaIPServer, ips[i].ip_address);
                break;
            }
        }
    }
    else
    {
        fprintf(stderr, "Failed to read IP address from command.\n");
    }

    if (pclose(cmd) == -1)
    {
        perror("pclose failed");
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
            ips[i].lease_time = leasing_time;
            return ips[i];
        }
        else
            c++;
    }
    if (c == n)
        errExit("No more available IPs!");
    errExit("Next available IP");
}

int check_mac_addr(uint8_t cache_addr[6], unsigned char incoming_addr[12])
{
    for (int i = 0; i < 6; i++)
        if (cache_addr[i] != incoming_addr[i])
            return 0;
    return 1;
}

int check_mac_in_cache(unsigned char *client_mac, int cache_size)
{
    for (int i = 0; i < cache_size; i++)
    {
        if (check_mac_addr(ips[i].mac_addr, client_mac))
        {
            if (ips[i].available == UNAVAILABLE)
            {
                ips[i].lease_time = leasing_time;
                return 1;
            }
            return 0;
        }
    }
    return 0;
}

void set_mac_to_addr(unsigned char *mac_addr, unsigned char *ip_addr, int cache_size)
{
    for (int i = 0; i < cache_size; i++)
    {
        if (strcmp(ips[i].ip_address, ip_addr) == 0)
        {
            memcpy(ips[i].mac_addr, mac_addr, 6);
            return;
        }
    }
}

void *decrement_lease_time(void *arg)
{
    int cache_size = *(int *)arg;
    while (1)
    {
        for (int i = 0; i < cache_size; i++)
        {
            // unsigned char parrot_addr[12] = {0x00,0x0C,0x29,0x62,0x16,0x2D}; // se poate sterge
            // if(check_mac_addr(ips[i].mac_addr,parrot_addr))                  // si asta
            //     if(ips[i].lease_time)                                        // si asta
            //         printf("Lease time-ul este: %d\n", ips[i].lease_time);   // si asta
            //     else                                                         // si asta
            //         printf("A expirat lease time-ul\n");                     // si asta
            if (ips[i].lease_time <= 0 && strcmp(ips[i].ip_address, adresaIPServer) != 0) // gasea adresa ip a serverului si o punea pe aia :))
                ips[i].available = AVAILABLE;
            else
                ips[i].lease_time--;
        }
        sleep(1);
        // printf("A trecut 1 secunda\n");
    }
}
