#ifndef SB_H
#define SB_H

#include <time.h>

typedef struct
{
    char sys_v6_gw[64];
    char sys_wanv4_ip[64];
} SBResult;

int sb_radius(int type, const char *auth_server_ip, const char *shared_secret,
                    const char *username, const char *password, const char *mac,
                    SBResult *result);

#endif // SB_H
