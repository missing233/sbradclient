#ifndef RADIUS_CLIENT_H
#define RADIUS_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#define PW_ACCESS_REQUEST 1
#define PW_ACCESS_ACCEPT 2
#define PW_ACCESS_REJECT 3

#define PW_USER_NAME 1
#define PW_CHAP_PASSWORD 3
#define PW_CHAP_CHALLENGE 60
#define PW_VENDOR_SPECIFIC 26

typedef struct
{
    uint8_t type;       // Attribute Type
    uint8_t is_vendor;  // 0 for standard, 1 for vendor-specific
    uint32_t vendor_id; // Vendor ID if is_vendor is 1

    // For single VSA
    uint8_t vendor_type; // Vendor-Type if single VSA
    const uint8_t *data; // Data if single VSA
    size_t data_len;     // Data length if single VSA

    // For multiple VSAs
    size_t vsa_count; // Number of VSAs
    struct
    {
        uint8_t vendor_type;
        const uint8_t *data;
        size_t data_len;
    } vsas[10]; // Adjust size as needed
} AVP;

size_t add_attribute(uint8_t *packet, size_t offset, const AVP *avp);
int radius_transact(const char *shared_secret, const AVP *avps, size_t avp_count,
                    uint8_t *recv_buffer, size_t *recv_len,
                    const char *auth_server_ip);

#endif // RADIUS_CLIENT_H
