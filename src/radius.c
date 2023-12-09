/*
 * Copyright 2018 Kenny Root
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

#include <nettle/md5.h>
#include <radcli/radcli.h>

#include "radius.h"

const char dictionary_dir[] = "./dictionary.softbank";
/*
const char kManufacturer[] = "foxconn";
const char kModel[] = "e-wmta2.3,V5.0.0.1.rc35";
const char kHwRev[] = "hw_rev_2.00";
*/
const char kManufacturer[] = "NTT-AT";
const char kModel[] = "BAPP";
const char kHwRev[] = "hw_rev_1.00";

uint32_t kVendorSoftbank = 22197;

const int kSbBBMac = 1;
const int kSbBBManufacturer = 2;
const int kSbBBModel = 3;
const int kSbBBHWRev = 4;

const int kSbIPv4LocalAddr = 204;
const int kSbIPv4TunnelEndpoint = 207;

char *get_bracketed_ip(const char *ip)
{
  if (ip == NULL)
    return NULL;

  int result;
  int is_ipv6 = 0;
  struct sockaddr_in sa;
  struct sockaddr_in6 sa6;

  result = inet_pton(AF_INET, ip, &(sa.sin_addr));
  if (result != 1)
  {
    result = inet_pton(AF_INET6, ip, &(sa6.sin6_addr));
    if (result == 1)
      is_ipv6 = 1;
    else
      return NULL;
  }

  size_t len = strlen(ip);
  char *bracketed_ip = (char *)malloc(len + (is_ipv6 ? 3 : 1));
  if (!bracketed_ip)
    return NULL;

  if (is_ipv6)
    sprintf(bracketed_ip, "[%s]", ip);
  else
    strcpy(bracketed_ip, ip);

  return bracketed_ip;
}

char *get_expanded_ipv6(const char *ip)
{
  struct in6_addr ipv6addr;
  if (inet_pton(AF_INET6, ip, &ipv6addr) != 1)
    return NULL;

  char *expanded_ip = malloc(40);
  if (!expanded_ip)
    return NULL;

  char *ptr = expanded_ip;
  for (int i = 0; i < 16; i += 2)
  {
    if (i != 0)
      *ptr++ = ':';
    ptr += sprintf(ptr, "%02x%02x", ipv6addr.s6_addr[i], ipv6addr.s6_addr[i + 1]);
  }

  return expanded_ip;
}

int radius_transact(const char *auth_server_ip, const char *shared_secret, const char *username, const char *password, const char *mac)
{
  rc_handle *rh = rc_new();
  if (rh == NULL)
  {
    fprintf(stderr, "ERROR: unable create new handle\n");
    return ERROR_RC;
  }

  if (rc_config_init(rh) == NULL)
  {
    fprintf(stderr, "unable to init rc\n");
    rc_destroy(rh);
    return ERROR_RC;
  }
  if (rc_add_config(rh, "dictionary", "/etc/radcli/dictionary", "config", 0) != 0)
  {
    fprintf(stderr, "ERROR: Unable to set dictionary\n");
    rc_destroy(rh);
    return ERROR_RC;
  }

  char *bracketed_ip = get_bracketed_ip(auth_server_ip);
  if (bracketed_ip == NULL)
  {
    fprintf(stderr, "ERROR: invalid address\n");
    rc_destroy(rh);
    return ERROR_RC;
  }

  char auth_server[512];
  snprintf(auth_server, sizeof(auth_server), "%s::%s", bracketed_ip, shared_secret);
  free(bracketed_ip);

  if (rc_add_config(rh, "authserver", auth_server, "config", 0) != 0)
  {
    fprintf(stderr, "ERROR: unable to set authserver\n");
    rc_destroy(rh);
    return ERROR_RC;
  }

  if (rc_add_config(rh, "radius_retries", "3", "config", 0) != 0)
  {
    fprintf(stderr, "ERROR: Unable to set radius_retries.\n");
    rc_destroy(rh);
    return ERROR_RC;
  }

  if (rc_add_config(rh, "radius_timeout", "5", "config", 0) != 0)
  {
    fprintf(stderr, "ERROR: Unable to set radius_timeout.\n");
    rc_destroy(rh);
    return ERROR_RC;
  }

  if (rc_test_config(rh, "config") != 0)
  {
    fprintf(stderr, "ERROR: config incomplete\n");
    rc_destroy(rh);
    return ERROR_RC;
  }

  const char *dictionary_path = rc_conf_str(rh, "dictionary");
  if (dictionary_path == NULL || rc_read_dictionary(rh, dictionary_path) != 0)
  {
    fprintf(stderr, "ERROR: Failed to initialize radius dictionary\n");
    rc_destroy(rh);
    return ERROR_RC;
  }

  if (rc_read_dictionary(rh, dictionary_dir) != 0)
  {
    fprintf(stderr, "ERROR: cannot read radius dictionary from %s\n", dictionary_dir);
    return ERROR_RC;
  }

  char *expanded_user_ip = get_expanded_ipv6(username);
  VALUE_PAIR *send;
  if (rc_avpair_add(rh, &send, PW_USER_NAME, expanded_user_ip, strlen(expanded_user_ip), VENDOR_NONE) == NULL)
  {
    free(expanded_user_ip);
    fprintf(stderr, "ERROR: cannot add USERNAME\n");
    rc_destroy(rh);
    return ERROR_RC;
  }
  free(expanded_user_ip);

  // Okay, this is gross, but the API sucks for this.
  // VALUE_PAIR *send_raw = send;

  char *challenge = malloc(MD5_DIGEST_SIZE);
  int rand_fd = open("/dev/urandom", O_RDONLY);
  ssize_t read_bytes = read(rand_fd, challenge, MD5_DIGEST_SIZE);
  close(rand_fd);

  size_t chap_password_len = 1 + strlen(password) + strlen(challenge);
  char *chap_password = malloc(chap_password_len + 1);

  // chap_password[0] = '\x01';
  chap_password[0] = '\x00';
  strcpy(chap_password + 1, password);
  strcat(chap_password, challenge);

  struct md5_ctx ctx;
  uint8_t hashed_bytes[MD5_DIGEST_SIZE];
  md5_init(&ctx);
  md5_update(&ctx, sizeof(chap_password), (const uint8_t *)chap_password);
  md5_digest(&ctx, MD5_DIGEST_SIZE, hashed_bytes);
  free(chap_password);

  size_t response_len = 1 + MD5_DIGEST_SIZE;
  char *response = malloc(response_len);

  // response[0] = '\x01';
  response[0] = '\x00';
  memcpy(response + 1, hashed_bytes, MD5_DIGEST_SIZE);

  if (rc_avpair_add(rh, &send, PW_CHAP_PASSWORD, response, response_len, VENDOR_NONE) == NULL)
  {
    fprintf(stderr, "ERROR: unable to add password\n");
    free(response);
    rc_destroy(rh);
    return ERROR_RC;
  }

  if (rc_avpair_add(rh, &send, kSbBBMac, mac, strlen(mac), kVendorSoftbank) == NULL)
  {
    fprintf(stderr, "ERROR: unable to set MAC:%s\n", mac);
    rc_destroy(rh);
    return ERROR_RC;
  }

  if (rc_avpair_add(rh, &send, kSbBBManufacturer, kManufacturer, strlen(kManufacturer), kVendorSoftbank) == NULL)
  {
    fprintf(stderr, "ERROR: unable to set manufacturer:%s\n", kManufacturer);
    rc_destroy(rh);
    return ERROR_RC;
  }

  if (rc_avpair_add(rh, &send, kSbBBModel, kModel, strlen(kModel), kVendorSoftbank) == NULL)
  {
    fprintf(stderr, "ERROR: unable to set model:%s\n", kModel);
    rc_destroy(rh);
    return ERROR_RC;
  }

  if (rc_avpair_add(rh, &send, kSbBBHWRev, kHwRev, strlen(kHwRev), kVendorSoftbank) == NULL)
  {
    fprintf(stderr, "ERROR: unable to set HW revision:%s\n", kHwRev);
    rc_destroy(rh);
    return ERROR_RC;
  }

  if (rc_avpair_add(rh, &send, PW_CHAP_CHALLENGE, challenge, MD5_DIGEST_SIZE, VENDOR_NONE) == NULL)
  {
    fprintf(stderr, "ERROR: cannot add CHAP challenge to packet\n");
    free(challenge);
    rc_destroy(rh);
    return ERROR_RC;
  }

  free(challenge);
  free(response);

  VALUE_PAIR *received = NULL;
  int result = rc_aaa(rh, 0, send, &received, NULL, 0, PW_ACCESS_REQUEST);
  if (result != OK_RC)
  {
    fprintf(stderr, " RADIUS Authentication failure (RC=%d)\n", result);
    rc_destroy(rh);
    return ERROR_RC;
  }

  VALUE_PAIR *vp_local_address = rc_avpair_get(received, kSbIPv4LocalAddr, kVendorSoftbank);
  if (vp_local_address == NULL)
    fprintf(stderr, "Local Address attribute is missing: %d/%d\n", kVendorSoftbank, kSbIPv4LocalAddr);

  VALUE_PAIR *vp_tunnel_endpoint = rc_avpair_get(received, kSbIPv4TunnelEndpoint, kVendorSoftbank);
  if (vp_tunnel_endpoint == NULL)
    fprintf(stderr, "Tunnel Endpoint attribute is missing: %d/%d\n", kVendorSoftbank, kSbIPv4TunnelEndpoint);

  char junk[1];
  char local_address[INET_ADDRSTRLEN];
  char tunnel_endpoint[INET6_ADDRSTRLEN];

  if (rc_avpair_tostr(rh, vp_local_address, junk, sizeof(junk), local_address, sizeof(local_address)) ||
      rc_avpair_tostr(rh, vp_tunnel_endpoint, junk, sizeof(junk), tunnel_endpoint, sizeof(tunnel_endpoint)))
  {
    fprintf(stderr, "Cannot find Local IPv4 Address or Tunnel Endpoint!\n");
    rc_destroy(rh);
    return ERROR_RC;
  }

  printf("%s %s\n", local_address, tunnel_endpoint);

  if (received)
    rc_avpair_free(received);

  rc_destroy(rh);

  return result;
}
