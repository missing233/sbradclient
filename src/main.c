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
#include <string.h>

#include "radius.h"

void print_usage(const char *executable_name);

const char *get_cmd_option(const char **begin, const char **end, const char *option)
{
  const char **itr = begin;
  while (itr < end)
  {
    if (strcmp(*itr, option) == 0)
    {
      if (++itr < end)
        return *itr;
      else
        return NULL;
    }
    ++itr;
  }
  return NULL;
}

int cmd_option_exists(const char **begin, const char **end, const char *option)
{
  const char **itr = begin;
  while (itr < end)
  {
    if (strcmp(*itr, option) == 0)
      return 1;
    ++itr;
  }
  return 0;
}

void print_usage(const char *executable_name)
{
  fprintf(stderr, "S*ftB*nk Hikari RADIUS authenticator\n");
  fprintf(stderr, "Usage:\t%s --ip <local IP> --mac <local MAC>\n", executable_name);
  fprintf(stderr, "\t\t--auth-server <RADIUS server IP> --shared-secret <RADIUS secret>\n");
  fprintf(stderr, "\t\t--password <RADIUS password>\n");
}

int main(int argc, char *argv[])
{
  int need_usage = 0;

  if (cmd_option_exists((const char **)argv, (const char **)(argv + argc), "--help"))
  {
    print_usage(argv[0]);
    return 1;
  }

  const char *ip = get_cmd_option((const char **)argv, (const char **)(argv + argc), "--ip");
  const char *mac = get_cmd_option((const char **)argv, (const char **)(argv + argc), "--mac");
  const char *auth_server = get_cmd_option((const char **)argv, (const char **)(argv + argc), "--auth-server");
  const char *shared_secret = get_cmd_option((const char **)argv, (const char **)(argv + argc), "--shared-secret");
  const char *password = get_cmd_option((const char **)argv, (const char **)(argv + argc), "--password");

  if (ip == NULL)
  {
    fprintf(stderr, "Missing local IP address\n");
    need_usage = 1;
  }
  if (mac == NULL)
  {
    fprintf(stderr, "Missing local MAC address\n");
    need_usage = 1;
  }
  if (auth_server == NULL)
  {
    fprintf(stderr, "Missing RADIUS auth server IP address\n");
    need_usage = 1;
  }
  if (shared_secret == NULL)
  {
    fprintf(stderr, "Missing RADIUS shared secret\n");
    need_usage = 1;
  }
  if (password == NULL)
  {
    fprintf(stderr, "Missing RADIUS password\n");
    need_usage = 1;
  }

  if (need_usage)
  {
    fprintf(stderr, "\n");
    print_usage(argv[0]);
    return 1;
  }

  return radius_transact(auth_server, shared_secret, ip, password, mac);
}
