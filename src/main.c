#include <stdio.h>
#include <stdlib.h>
#include "sb.h"

int main(int argc, char *argv[])
{
    if (argc != 7)
    {
        fprintf(stderr, "Usage: %s <type> <auth_server_ip> <shared_secret> <username> <password> <mac>\n", argv[0]);
        return EXIT_FAILURE;
    }

    srand(time(NULL));

    int type = atoi(argv[1]);
    if (type != 0 && type != 1)
    {
        fprintf(stderr, "Invalid type. Must be 0 or 1.\n");
        return EXIT_FAILURE;
    }

    const char *auth_server_ip = argv[2];
    const char *shared_secret = argv[3];
    const char *username = argv[4];
    const char *password = argv[5];
    const char *mac = argv[6];

    SBResult result;
    int ret = sb_radius(type, auth_server_ip, shared_secret,
                              username, password, mac, &result);

    if (ret == EXIT_SUCCESS)
    {
        printf("Sys_WANv4_IP: %s\n", result.sys_wanv4_ip);
        printf("Sys_v6_gw: %s\n", result.sys_v6_gw);
    }
    else
    {
        fprintf(stderr, "Authentication failed.\n");
    }

    return ret;
}
