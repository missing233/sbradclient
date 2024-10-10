#include "radius_client.h"
#include "md5.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>

size_t add_attribute(uint8_t *packet, size_t offset, const AVP *avp)
{
    if (!avp->is_vendor)
    {
        // Standard RADIUS attribute
        if (avp->data_len + 2 > 255)
        {
            fprintf(stderr, "Attribute too long\n");
            exit(EXIT_FAILURE);
        }
        packet[offset++] = avp->type;
        packet[offset++] = (uint8_t)(avp->data_len + 2);
        memcpy(packet + offset, avp->data, avp->data_len);
        offset += avp->data_len;
    }
    else
    {
        // Vendor-Specific Attribute
        uint8_t vsa_buffer[256];
        size_t vsa_len = 0;

        if (avp->vsa_count == 0)
        {
            // Single VSA
            if (avp->data_len + 2 > 255)
            {
                fprintf(stderr, "VSA too long\n");
                exit(EXIT_FAILURE);
            }
            vsa_buffer[vsa_len++] = avp->vendor_type;
            vsa_buffer[vsa_len++] = (uint8_t)(avp->data_len + 2);
            memcpy(vsa_buffer + vsa_len, avp->data, avp->data_len);
            vsa_len += avp->data_len;
        }
        else
        {
            // Multiple VSAs
            for (size_t i = 0; i < avp->vsa_count; i++)
            {
                if (avp->vsas[i].data_len + 2 > 255)
                {
                    fprintf(stderr, "VSA too long\n");
                    exit(EXIT_FAILURE);
                }
                vsa_buffer[vsa_len++] = avp->vsas[i].vendor_type;
                vsa_buffer[vsa_len++] = (uint8_t)(avp->vsas[i].data_len + 2);
                memcpy(vsa_buffer + vsa_len, avp->vsas[i].data, avp->vsas[i].data_len);
                vsa_len += avp->vsas[i].data_len;
            }
        }

        if (vsa_len + 6 > 255)
        {
            fprintf(stderr, "Vendor-Specific Attribute too long\n");
            exit(EXIT_FAILURE);
        }

        packet[offset++] = PW_VENDOR_SPECIFIC;
        packet[offset++] = (uint8_t)(vsa_len + 6);

        // Vendor-ID
        uint32_t vendor_id = htonl(avp->vendor_id);
        memcpy(packet + offset, &vendor_id, 4);
        offset += 4;

        // Copy VSA data
        memcpy(packet + offset, vsa_buffer, vsa_len);
        offset += vsa_len;
    }

    return offset;
}

int radius_transact(const char *shared_secret, const AVP *avps, size_t avp_count,
                    uint8_t *recv_buffer, size_t *recv_len,
                    const char *auth_server_ip)
{
    uint8_t packet[4096];
    size_t packet_len = 0;

    // Generate random Authenticator
    uint8_t authenticator[16];
    int rand_fd = open("/dev/urandom", O_RDONLY);
    if (rand_fd < 0)
    {
        perror("open /dev/urandom");
        return EXIT_FAILURE;
    }
    ssize_t bytes_read = read(rand_fd, authenticator, sizeof(authenticator));
    if (bytes_read != sizeof(authenticator))
    {
        perror("read /dev/urandom");
        close(rand_fd);
        return EXIT_FAILURE;
    }
    close(rand_fd);

    // Build RADIUS packet header
    uint8_t code = PW_ACCESS_REQUEST;
    uint8_t identifier = (uint8_t)(rand() % 256);
    printf("Packet Identifier: %d\n", identifier);

    packet[0] = code;
    packet[1] = identifier;
    packet_len = 20;                       // Header size
    memcpy(packet + 4, authenticator, 16); // Set Authenticator

    // Add attributes
    for (size_t i = 0; i < avp_count; i++)
    {
        packet_len = add_attribute(packet, packet_len, &avps[i]);
    }

    // Update length in header
    uint16_t length = htons((uint16_t)packet_len);
    memcpy(packet + 2, &length, 2);

    // Prepare socket
    int sockfd;
    struct addrinfo hints, *res;
    int rv;
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", 1812);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    if ((rv = getaddrinfo(auth_server_ip, port_str, &hints, &res)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return EXIT_FAILURE;
    }

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    if (sockfd < 0)
    {
        perror("socket");
        freeaddrinfo(res);
        return EXIT_FAILURE;
    }

    // Set receive timeout
    struct timeval timeout = {5, 0}; // 5 seconds timeout
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Initialize retry counter
    int max_retries = 3;
    int retries = 0;
    ssize_t recv_bytes = -1;
    struct sockaddr_storage their_addr;
    socklen_t addr_len = sizeof(their_addr);

    while (retries < max_retries)
    {
        // Send request
        ssize_t sent_bytes = sendto(sockfd, packet, packet_len, 0, res->ai_addr, res->ai_addrlen);
        if (sent_bytes != (ssize_t)packet_len)
        {
            perror("sendto");
            close(sockfd);
            freeaddrinfo(res);
            return EXIT_FAILURE;
        }

        // Receive response
        recv_bytes = recvfrom(sockfd, recv_buffer, *recv_len, 0, (struct sockaddr *)&their_addr, &addr_len);
        if (recv_bytes < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                retries++;
                fprintf(stderr, "Warning: No response from server, retrying... (%d/%d)\n", retries, max_retries);
                continue; // Retry
            }
            else
            {
                perror("recvfrom");
                close(sockfd);
                freeaddrinfo(res);
                return EXIT_FAILURE;
            }
        }
        // Received response, break the loop
        break;
    }

    if (recv_bytes < 0)
    {
        fprintf(stderr, "Error: No response from server after %d attempts.\n", max_retries);
        close(sockfd);
        freeaddrinfo(res);
        return EXIT_FAILURE;
    }

    // Verify Response Authenticator
    if (recv_bytes >= 20)
    {
        uint8_t recv_authenticator[16];
        memcpy(recv_authenticator, recv_buffer + 4, 16);

        // Prepare data for MD5 hash
        uint8_t md5_data[4096];
        memcpy(md5_data, recv_buffer, 4);                         // Code + Identifier + Length
        memcpy(md5_data + 4, authenticator, 16);     // Request Authenticator
        memcpy(md5_data + 20, recv_buffer + 20, recv_bytes - 20); // Attributes
        size_t md5_data_len = recv_bytes;

        // Append shared_secret
        size_t secret_len = strlen(shared_secret);
        memcpy(md5_data + md5_data_len, shared_secret, secret_len);
        md5_data_len += secret_len;

        // Calculate MD5 hash
        uint8_t expected_authenticator[16];
        MD5_CTX md5_ctx;
        MD5_Init(&md5_ctx);
        MD5_Update(&md5_ctx, md5_data, md5_data_len);
        MD5_Final(expected_authenticator, &md5_ctx);

        if (memcmp(recv_authenticator, expected_authenticator, 16) != 0)
        {
            fprintf(stderr, "Invalid Response Authenticator\n");
            close(sockfd);
            freeaddrinfo(res);
            return EXIT_FAILURE;
        }
    }
    else
    {
        fprintf(stderr, "Received invalid RADIUS packet\n");
        close(sockfd);
        freeaddrinfo(res);
        return EXIT_FAILURE;
    }

    close(sockfd);
    freeaddrinfo(res);

    *recv_len = (size_t)recv_bytes;
    return EXIT_SUCCESS;
}
