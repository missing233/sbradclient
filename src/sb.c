#include "sb.h"
#include "radius_client.h"
#include "md5.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

uint32_t kVendorSb = 22197;
const int kSbBBMac = 1;
const int kSbBBManufacturer = 2;
const int kSbBBModel = 3;
const int kSbBBHWRev = 4;

const int kSbWANv4IP = 204;
const int kSbV6gw = 207;

void create_challenge(uint8_t *challenge, size_t len)
{
    int rand_fd = open("/dev/urandom", O_RDONLY);
    if (rand_fd < 0)
    {
        perror("open /dev/urandom");
        exit(EXIT_FAILURE);
    }
    ssize_t read_bytes = read(rand_fd, challenge, len);
    if (read_bytes != (ssize_t)len)
    {
        perror("read /dev/urandom");
        close(rand_fd);
        exit(EXIT_FAILURE);
    }
    close(rand_fd);
}

void compute_chap_response(uint8_t chap_id, const char *password,
                           const uint8_t *challenge, size_t challenge_len,
                           uint8_t *response)
{
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, &chap_id, 1);
    MD5_Update(&ctx, (const unsigned char *)password, strlen(password));
    MD5_Update(&ctx, challenge, challenge_len);
    MD5_Final(response, &ctx);
}

void extract_vsas(const uint8_t *packet, size_t len, SBResult *result)
{
    if (len < 20)
    {
        fprintf(stderr, "Invalid RADIUS packet length\n");
        return;
    }

    uint8_t code = packet[0];
    uint8_t identifier = packet[1];
    uint16_t length = ntohs(*(uint16_t *)(packet + 2));

    if (length != len)
    {
        fprintf(stderr, "Invalid RADIUS packet length field\n");
        return;
    }

    const uint8_t *attributes = packet + 20;
    size_t attr_len = len - 20;

    while (attr_len >= 2)
    {
        uint8_t type = attributes[0];
        uint8_t attr_length = attributes[1];

        if (attr_length < 2 || attr_length > attr_len)
        {
            fprintf(stderr, "Invalid attribute length\n");
            break;
        }

        const uint8_t *attr_data = attributes + 2;
        size_t data_len = attr_length - 2;

        if (type == PW_VENDOR_SPECIFIC)
        {
            if (data_len < 6)
            {
                fprintf(stderr, "Invalid vendor-specific attribute\n");
                break;
            }

            uint32_t vendor_id = ntohl(*(uint32_t *)attr_data);
            if (vendor_id == kVendorSb)
            {
                const uint8_t *vsa_data = attr_data + 4;
                size_t vsa_len = data_len - 4;

                while (vsa_len >= 2)
                {
                    uint8_t vsa_type = vsa_data[0];
                    uint8_t vsa_length = vsa_data[1];

                    if (vsa_length < 2 || vsa_length > vsa_len)
                    {
                        fprintf(stderr, "Invalid VSA length\n");
                        break;
                    }

                    const uint8_t *vsa_value = vsa_data + 2;
                    size_t vsa_value_len = vsa_length - 2;

                    if (vsa_type == kSbV6gw && vsa_value_len > 0)
                    {
                        // Sys_v6_gw
                        char addr_str[64];
                        inet_ntop(AF_INET6, vsa_value, addr_str, sizeof(addr_str));
                        strncpy(result->sys_v6_gw, addr_str, sizeof(result->sys_v6_gw) - 1);
                        result->sys_v6_gw[sizeof(result->sys_v6_gw) - 1] = '\0';
                    }
                    else if (vsa_type == kSbWANv4IP && vsa_value_len > 0)
                    {
                        // Sys_WANv4_IP
                        char addr_str[64];
                        inet_ntop(AF_INET, vsa_value, addr_str, sizeof(addr_str));
                        strncpy(result->sys_wanv4_ip, addr_str, sizeof(result->sys_wanv4_ip) - 1);
                        result->sys_wanv4_ip[sizeof(result->sys_wanv4_ip) - 1] = '\0';
                    }

                    vsa_data += vsa_length;
                    vsa_len -= vsa_length;
                }
            }
        }

        attributes += attr_length;
        attr_len -= attr_length;
    }
}

int sb_radius(int type, const char *auth_server_ip, const char *shared_secret,
                    const char *username, const char *password, const char *mac,
                    SBResult *result)
{
    // Prepare AVPs
    AVP avps[10];
    size_t avp_count = 0;

    // Set parameters based on type
    const char *Manufacturer;
    const char *Model;
    const char *HwRev;
    uint8_t response;

    if (type == 1)
    {
        Manufacturer = "foxconn";
        Model = "e-wmta2.3,V5.0.0.1.rc35";
        HwRev = "hw_rev_2.00";
        response = '\x01';
    }
    else
    {
        Manufacturer = "NTT-AT";
        Model = "BAPP";
        HwRev = "hw_rev_1.00";
        response = '\x00';
    }

    // USER_NAME attribute
    memset(&avps[avp_count], 0, sizeof(AVP));
    avps[avp_count].type = PW_USER_NAME;
    avps[avp_count].is_vendor = 0;
    avps[avp_count].data = (const uint8_t *)username;
    avps[avp_count].data_len = strlen(username);
    avp_count++;

    // Create CHAP challenge
    uint8_t challenge[16];
    create_challenge(challenge, sizeof(challenge));

    // CHAP_CHALLENGE attribute
    memset(&avps[avp_count], 0, sizeof(AVP));
    avps[avp_count].type = PW_CHAP_CHALLENGE;
    avps[avp_count].is_vendor = 0;
    avps[avp_count].data = challenge;
    avps[avp_count].data_len = sizeof(challenge);
    avp_count++;

    // CHAP_PASSWORD attribute
    uint8_t chap_id = response;
    uint8_t chap_response[17];
    chap_response[0] = chap_id;
    compute_chap_response(chap_id, password, challenge, sizeof(challenge),
                          chap_response + 1);

    memset(&avps[avp_count], 0, sizeof(AVP));
    avps[avp_count].type = PW_CHAP_PASSWORD;
    avps[avp_count].is_vendor = 0;
    avps[avp_count].data = chap_response;
    avps[avp_count].data_len = sizeof(chap_response);
    avp_count++;

    // Add Vendor-Specific Attributes
    if (type == 1)
    {
        // One AVP per VSA
        // Add CPE-MAC-Address
        memset(&avps[avp_count], 0, sizeof(AVP));
        avps[avp_count].is_vendor = 1;
        avps[avp_count].vendor_id = kVendorSb;
        avps[avp_count].vendor_type = kSbBBMac;
        avps[avp_count].data = (const uint8_t *)mac;
        avps[avp_count].data_len = strlen(mac);
        avp_count++;

        // Add CPE-Manufacturer
        memset(&avps[avp_count], 0, sizeof(AVP));
        avps[avp_count].is_vendor = 1;
        avps[avp_count].vendor_id = kVendorSb;
        avps[avp_count].vendor_type = kSbBBManufacturer;
        avps[avp_count].data = (const uint8_t *)Manufacturer;
        avps[avp_count].data_len = strlen(Manufacturer);
        avp_count++;

        // Add CPE-Model
        memset(&avps[avp_count], 0, sizeof(AVP));
        avps[avp_count].is_vendor = 1;
        avps[avp_count].vendor_id = kVendorSb;
        avps[avp_count].vendor_type = kSbBBModel;
        avps[avp_count].data = (const uint8_t *)Model;
        avps[avp_count].data_len = strlen(Model);
        avp_count++;

        // Add CPE-HW-Revision
        memset(&avps[avp_count], 0, sizeof(AVP));
        avps[avp_count].is_vendor = 1;
        avps[avp_count].vendor_id = kVendorSb;
        avps[avp_count].vendor_type = kSbBBHWRev;
        avps[avp_count].data = (const uint8_t *)HwRev;
        avps[avp_count].data_len = strlen(HwRev);
        avp_count++;
    }
    else
    {
        // One AVP containing multiple VSAs
        memset(&avps[avp_count], 0, sizeof(AVP));
        avps[avp_count].is_vendor = 1;
        avps[avp_count].vendor_id = kVendorSb;
        avps[avp_count].vsa_count = 4;

        // Add CPE-MAC-Address
        avps[avp_count].vsas[0].vendor_type = kSbBBMac;
        avps[avp_count].vsas[0].data = (const uint8_t *)mac;
        avps[avp_count].vsas[0].data_len = strlen(mac);

        // Add CPE-Manufacturer
        avps[avp_count].vsas[1].vendor_type = kSbBBManufacturer;
        avps[avp_count].vsas[1].data = (const uint8_t *)Manufacturer;
        avps[avp_count].vsas[1].data_len = strlen(Manufacturer);

        // Add CPE-Model
        avps[avp_count].vsas[2].vendor_type = kSbBBModel;
        avps[avp_count].vsas[2].data = (const uint8_t *)Model;
        avps[avp_count].vsas[2].data_len = strlen(Model);

        // Add CPE-HW-Revision
        avps[avp_count].vsas[3].vendor_type = kSbBBHWRev;
        avps[avp_count].vsas[3].data = (const uint8_t *)HwRev;
        avps[avp_count].vsas[3].data_len = strlen(HwRev);

        avp_count++;
    }

    // Send RADIUS request and receive response
    uint8_t recv_buffer[4096];
    size_t recv_len = sizeof(recv_buffer);
    int result_code = radius_transact(shared_secret, avps, avp_count,
                                      recv_buffer, &recv_len, auth_server_ip);

    if (result_code != EXIT_SUCCESS)
    {
        fprintf(stderr, "RADIUS transaction failed\n");
        return EXIT_FAILURE;
    }

    // Extract required information from response
    if (recv_buffer[0] == PW_ACCESS_ACCEPT)
    {
        extract_vsas(recv_buffer, recv_len, result);
    }
    else if (recv_buffer[0] == PW_ACCESS_REJECT)
    {
        fprintf(stderr, "Access Reject\n");
        return EXIT_FAILURE;
    }
    else
    {
        fprintf(stderr, "Unknown RADIUS response code: %d\n", recv_buffer[0]);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
