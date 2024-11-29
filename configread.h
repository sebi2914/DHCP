#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>

char *readconfigfile();

struct ip_cache_entry
{
    unsigned char ip_address[16];
    uint8_t available;
    uint16_t lease_time;
};