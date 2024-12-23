#include "configread.h"
#include "dhcp_utils.h"
#include <pthread.h>

int main()
{
    char *configfile = readconfigfile();
    parseConfigFile(configfile);
    int nrTotalIps;
    cacheIpAddresses(&nrTotalIps);

    struct ip_cache_entry nextAvailableIp;

    pthread_t timer;  
    pthread_create(&timer,NULL, decrement_lease_time, &nrTotalIps);

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

    while (1)
    {
        memset(&packet, 0, sizeof(packet));
        recvfrom(sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)&client_addr, &client_len);

        unsigned char *options = packet.options;
        options += 4;

        uint8_t message_type = get_message_type(options);
        uint32_t requested_ip;

        switch (message_type)
        {
        case 1:
            printf("DHCP Discover received\n");
            nextAvailableIp = getNextAvailableIp(nrTotalIps);
            init_dhcp_packet(&packet, nextAvailableIp.ip_address);

            set_mac_to_addr(packet.chaddr,nextAvailableIp.ip_address,nrTotalIps);

            set_dhcp_packet_options(&options, &offer_code, &dhcp_identifier, &subnet_mask, &default_gateway, &broadcast_address, &lease_time, dns_servers);

            int actual_packet_size = size_to_send(packet.options);

            memset(&client_addr, 0, client_len);
            client_addr.sin_family = AF_INET;
            client_addr.sin_addr.s_addr = INADDR_BROADCAST;
            client_addr.sin_port = htons(68);

            if (sendto(sockfd, &packet, actual_packet_size, 0, (struct sockaddr *)&client_addr, client_len) < 0)
            {
                printf("Failed to send DHCP Offer");
            }
            else
                printf("DHCP Offer sent to client\n");
            break;
        case 3:
            printf("\nDHCP Request received\n");
            if(packet.ciaddr == 0)
                requested_ip = INADDR_BROADCAST;
            else
                requested_ip = packet.ciaddr;

            if (check_mac_in_cache(packet.chaddr,nrTotalIps))
            {
                init_dhcp_packet(&packet, nextAvailableIp.ip_address);

                set_dhcp_packet_options(&options, &ack_code, &dhcp_identifier, &subnet_mask, &default_gateway, &broadcast_address, &lease_time, dns_servers);

                memset(&client_addr, 0, client_len);
                client_addr.sin_family = AF_INET;
                client_addr.sin_addr.s_addr = requested_ip;
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
            break;
        default:
            break;
        }
    }

    close(sockfd);

    return 0;
}
