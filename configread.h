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

extern char *subnet, *mask, *gateway, *dns1, *dns2, *domain;

struct ip_cache_entry
{
    unsigned char ip_address[16];
    uint8_t available;
    uint16_t lease_time;
};

extern struct ip_cache_entry *ips;

char *readconfigfile();

void errExit(const char *msg);

void parseConfigFile(char *buff);

int getType(char *buff);

struct ip_cache_entry *cacheIpAddresses(int *n);

void setUnavailable(int totalAddresses);

struct ip_cache_entry getNextAvailableIp(int n);

void checkAvailability(int n);
