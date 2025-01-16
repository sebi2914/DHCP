#include "dhcp_utils.h"

#define LOG_FILE "logs.txt"

pthread_t threads[NR_THREADS];
int available_thread[NR_THREADS];
pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;

int log_fd = -1;

int main()
{
    setvbuf(stdout, NULL, _IONBF, 0);
    sigset_t set;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));

    sa.sa_flags = SA_RESTART;
    sa.sa_handler = signal_handler;

    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGINT);
    sigaddset(&sa.sa_mask, SIGTERM);
    sigaddset(&sa.sa_mask, SIGSTOP);

    if (sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction SIGINT");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1)
    {
        perror("sigaction SIGTERM");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGQUIT, &sa, NULL) == -1)
    {
        perror("sigaction SIGQUIT");
        exit(EXIT_FAILURE);
    }

    log_fd = open(LOG_FILE, O_WRONLY);
    if (log_fd == -1)
    {
        perror("open log file");
        exit(errno);
    }

    char *configfile = readconfigfile();
    parseConfigFile(configfile);
    int nrTotalIps;
    cacheIpAddresses(&nrTotalIps);

    pthread_t timer;
    pthread_create(&timer, NULL, decrement_lease_time, &nrTotalIps);

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

    struct sockaddr_in server_addr, client_addr;
    struct dhcp_packet packet;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(67);

    socklen_t client_len = sizeof(client_addr);
    memset(&client_addr, 0, client_len);
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = INADDR_BROADCAST;
    client_addr.sin_port = htons(68);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        printf("Bind failed");
        close(sockfd);
        exit(errno);
    }

    printf("DHCP Server is running...\n");
    printInLogFile("DHCP Server is running...\n");
    uint8_t offer_code = 2;
    uint8_t ack_code = 5;
    uint32_t dhcp_identifier = inet_addr(adresaIPServer);
    uint32_t subnet_mask = inet_addr(mask);
    uint32_t default_gateway = inet_addr(gateway);
    uint32_t broadcast_address = inet_addr(broadcastIP);
    uint32_t lease_time = htonl(leasing_time);
    uint32_t dns_servers[2];
    dns_servers[0] = inet_addr(dns1);
    dns_servers[1] = inet_addr(dns2);

    for (int i = 0; i < NR_THREADS; i++)
    {
        available_thread[i] = THREAD_AVAILABLE;
    }

    struct ip_cache_entry nextAvailableIp;
    struct threadsStruct DHCPStruct;

    nextAvailableIp = getNextAvailableIp(nrTotalIps);
    while (1)
    {
        printf("\nAvailable ip: %s\n", nextAvailableIp.ip_address);

        char buff[100] = "Available IP Address: ";
        strcat(buff, nextAvailableIp.ip_address);
        strcat(buff, "\n");
        printInLogFile(buff);

        memset(&packet, 0, sizeof(packet));
        recvfrom(sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)&client_addr, &client_len);

        unsigned char *options = packet.options;
        options += 4;

        uint8_t message_type = get_message_type(options);

        int found_available_thread = 0;

        pthread_mutex_lock(&mutex_struct);
        DHCPStruct.nrTotalIps = nrTotalIps;
        memcpy(&(DHCPStruct.nextAvailableIp), &nextAvailableIp, sizeof(nextAvailableIp));
        memcpy(&DHCPStruct.packet, &packet, sizeof(packet));
        // DHCPStruct.code = offer_code;
        DHCPStruct.dhcp_identifier = dhcp_identifier;
        DHCPStruct.subnet_mask = subnet_mask;
        DHCPStruct.default_gateway = default_gateway;
        DHCPStruct.broadcast_address = broadcast_address;
        DHCPStruct.lease_time = lease_time;
        DHCPStruct.dns_servers[0] = dns_servers[0];
        DHCPStruct.dns_servers[1] = dns_servers[1];
        memcpy(&DHCPStruct.client_addr, &client_addr, sizeof(client_addr));
        DHCPStruct.client_len = client_len;
        DHCPStruct.sockfd = sockfd;
        pthread_mutex_unlock(&mutex_struct);

        switch (message_type)
        {
        case 1:
            printInLogFile("DHCP Discover received!\n");
            printf("\nDHCP Discover received\n");
            DHCPStruct.code = offer_code;
            while (!found_available_thread)
            {
                for (int i = 0; i < NR_THREADS; i++)
                {
                    printf("%d,", i);
                    fflush(stdout);
                    pthread_mutex_lock(&thread_mutex);
                    if (available_thread[i] == THREAD_AVAILABLE)
                    {
                        DHCPStruct.thread_index = i;
                        available_thread[i] = THREAD_UNAVAILABLE;
                        pthread_create(&threads[i], NULL, DHCPDiscover, &DHCPStruct);
                        found_available_thread = 1;
                        pthread_mutex_unlock(&thread_mutex);
                        break;
                    }
                    pthread_mutex_unlock(&thread_mutex);
                }
            }
            found_available_thread = 0;

            break;
        case 3:
            printInLogFile("DHCP Request received!\n");
            printf("\nDHCP Request received\n");
            DHCPStruct.code = ack_code;
            while (!found_available_thread)
            {
                for (int i = 0; i < NR_THREADS; i++)
                {
                    pthread_mutex_lock(&thread_mutex);
                    if (available_thread[i] == THREAD_AVAILABLE)
                    {
                        DHCPStruct.thread_index = i;
                        available_thread[i] = THREAD_UNAVAILABLE;
                        pthread_create(&threads[i], NULL, DHCPSRequest, &DHCPStruct);
                        found_available_thread = 1;
                        pthread_mutex_unlock(&thread_mutex);
                        break;
                    }
                    pthread_mutex_unlock(&thread_mutex);
                }
            }
            found_available_thread = 0;

            break;
        default:
            break;
        }
    }

    joinAllWorkingThreads();

    close(sockfd);
    close(log_fd);

    return 0;
}
