#include "dhcp_utils.h"

pthread_mutex_t mutex_struct = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t mutex_log = PTHREAD_MUTEX_INITIALIZER;

char *getCurrentTimeAndDate()
{
    char *buffer = malloc(50);
    if (buffer == NULL)
    {
        perror("malloc failed");
        return NULL;
    }

    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    snprintf(buffer, 50, "[%02d:%02d:%02d] [%02d.%02d.%04d]",
             t->tm_hour, t->tm_min, t->tm_sec,
             t->tm_mday, t->tm_mon + 1, t->tm_year + 1900);

    return buffer;
}

void printInLogFile(const char buff[])
{
    char *crtTime = getCurrentTimeAndDate();
    if (crtTime == NULL)
    {
        fprintf(stderr, "Failed to get current time\n");
        return;
    }

    char logEntry[1024];
    snprintf(logEntry, sizeof(logEntry), "%s\t%s\n", crtTime, buff);

    free(crtTime);

    pthread_mutex_lock(&mutex_log);
    if (write(log_fd, logEntry, strlen(logEntry)) == -1)
    {
        perror("write failed");
    }
    pthread_mutex_unlock(&mutex_log);
}

void joinAllWorkingThreads()
{
    for (int i = 0; i < NR_THREADS; i++)
    {
        pthread_mutex_lock(&thread_mutex);
        if (available_thread[i] == THREAD_UNAVAILABLE)
        {
            pthread_mutex_unlock(&thread_mutex);
            pthread_join(threads[i], NULL);
        }
        else
        {
            pthread_mutex_unlock(&thread_mutex);
        }
    }
}

void signal_handler(int signum)
{

    char c;
    if (signum == SIGINT || signum == SIGTERM || signum == SIGQUIT)
    {
        sigset_t set, old_set;
        sigemptyset(&set);
        sigaddset(&set, SIGINT);
        sigaddset(&set, SIGTERM);
        sigaddset(&set, SIGQUIT);
        sigprocmask(SIG_BLOCK, &set, &old_set);

        printf("\n[%u] Are you sure you want to close the server?\t[Y/N]\n", getpid());
        read(STDIN_FILENO, &c, 1);
        if (c == 'y' || c == 'Y')
        {
            printf("\nServer terminated! [%d]\n", signum);
            joinAllWorkingThreads();
            exit(signum);
        }
        else if (c == 'n' || c == 'N')
        {
            printf("\nServer still running...\n");
            return;
        }
        else
        {
            printf("\nUnrecognized command! Continuing...\n");
            return;
        }
    }
}

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
    printInLogFile("Initializing DHCP Packet...\n");
    packet->op = 2;
    packet->htype = 1;
    packet->hlen = 6;
    packet->hops = 0;
    // transaction id is set by client
    // secs is set by client
    packet->flags = htons(0x8000);
    // ciaddr is set by client
    packet->yiaddr = inet_addr(ip_address);
    packet->siaddr = inet_addr(adresaIPServer);
    packet->giaddr = inet_addr(gateway);
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

void set_dhcp_packet_options(unsigned char **options, uint8_t *offer_code, uint32_t *dhcp_identifier, uint32_t *subnet_mask,
                             uint32_t *default_gateway, uint32_t *broadcast_address, uint32_t *lease_time, uint32_t *dns_servers)
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

uint8_t get_message_type(unsigned char *option_ptr)
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

void *DHCPDiscover(void *arg)
{
    pthread_mutex_lock(&mutex_struct);
    struct threadsStruct *initialDHCPD = (struct threadsStruct *)arg;
    struct threadsStruct stackDHCPD;
    struct threadsStruct *DHCPD = &stackDHCPD;
    memcpy(DHCPD, initialDHCPD, sizeof(struct threadsStruct));
    pthread_mutex_unlock(&mutex_struct);
    init_dhcp_packet(&(DHCPD->packet), DHCPD->nextAvailableIp.ip_address);
    set_mac_to_addr(DHCPD->packet.chaddr, DHCPD->nextAvailableIp.ip_address, DHCPD->nrTotalIps);

    unsigned char *options = DHCPD->packet.options;
    options += 4;
    set_dhcp_packet_options(&(options), &(DHCPD->code), &(DHCPD->dhcp_identifier), &(DHCPD->subnet_mask), &(DHCPD->default_gateway),
                            &(DHCPD->broadcast_address), &(DHCPD->lease_time), DHCPD->dns_servers);
    int actual_packet_size = size_to_send(DHCPD->packet.options);

    memset(&(DHCPD->client_addr), 0, DHCPD->client_len);
    DHCPD->client_addr.sin_family = AF_INET;
    DHCPD->client_addr.sin_addr.s_addr = INADDR_BROADCAST;
    DHCPD->client_addr.sin_port = htons(68);

    if (sendto(DHCPD->sockfd, &(DHCPD->packet), actual_packet_size, 0, (struct sockaddr *)&(DHCPD->client_addr), DHCPD->client_len) < 0)
    {
        printInLogFile("Failed to send DHCP Offer");
        printf("Failed to send DHCP Offer");
    }
    else
    {
        printInLogFile("DHCP Offer sent to client\n");
        printf("DHCP Offer sent to client\n");
    }
    available_thread[DHCPD->thread_index] = AVAILABLE;
    pthread_exit(NULL);
}

void *DHCPSRequest(void *arg)
{
    pthread_mutex_lock(&mutex_struct);
    struct threadsStruct *initialDHCPR = (struct threadsStruct *)arg;
    struct threadsStruct stackDHCPR;
    struct threadsStruct *DHCPR = &stackDHCPR;
    memcpy(DHCPR, initialDHCPR, sizeof(struct threadsStruct));
    int inCache = check_mac_in_cache(DHCPR->packet.chaddr, DHCPR->nrTotalIps);
    pthread_mutex_unlock(&mutex_struct);
    uint32_t requested_ip;
    if (DHCPR->packet.ciaddr == 0)
        requested_ip = INADDR_BROADCAST;
    else
        requested_ip = DHCPR->packet.ciaddr;
    printf("IN  CACHE: %d\n", inCache);
    if (inCache)
    {
        init_dhcp_packet(&(DHCPR->packet), DHCPR->nextAvailableIp.ip_address);
        unsigned char *options = DHCPR->packet.options;
        options += 4;
        set_dhcp_packet_options(&(options), &(DHCPR->code), &(DHCPR->dhcp_identifier), &(DHCPR->subnet_mask), &(DHCPR->default_gateway),
                                &(DHCPR->broadcast_address), &(DHCPR->lease_time), DHCPR->dns_servers);
        memset(&(DHCPR->client_addr), 0, DHCPR->client_len);
        DHCPR->client_addr.sin_family = AF_INET;
        DHCPR->client_addr.sin_addr.s_addr = requested_ip;
        DHCPR->client_addr.sin_port = htons(68);
        int actual_packet_size = size_to_send(DHCPR->packet.options);
        if (sendto(DHCPR->sockfd, &(DHCPR->packet), actual_packet_size, 0, (struct sockaddr *)&(DHCPR->client_addr), DHCPR->client_len) < 0)
        {
            printInLogFile("Failed to send DHCP ACK\n");
            printf("Failed to send DHCP ACK\n");
        }
        else
        {
            printInLogFile("DHCP ACK sent to client\n");
            printf("DHCP ACK sent to client\n");
        }
    }
    else
    {
        printInLogFile("IP Address is not available!\n");
        printf("IP Address is not available!\n");
    }
    available_thread[DHCPR->thread_index] = AVAILABLE;
    pthread_exit(NULL);
}