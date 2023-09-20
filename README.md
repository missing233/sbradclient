# sofutobanku
Setup utility for a certain Hikari provider in Japan

## Linux server setup

This explains a setup that uses the NetworkManager stack to connect to the
Internet. Distributions like Fedora Linux use this software to control the
network stack.

* External interface
  * Dibbler is the only DHCPv6 client suitable for our use. Make sure to put
    the Auth Server, Shared Secret, and Password in `/etc/sysconfig/sofutobanku`.
    Use the following config file with `<Internet interface>` substituted for
    the right values for your configuration.

`/etc/dibbler/client.conf`:
```
# Dibbler client config for SoftBank Hikari
duid-type duid-ll
inactive-mode
skip-confirm
log-mode short
log-level 7
script "/etc/softubanku/dibbler.sh"
t1 0
t2 0
reconfigure-accept 1

# You can specify downlink interfaces:
#downlink-prefix-ifaces "eth1", "eth2", "wifi0"
# Or set it off to manually configure them elsewhere:
#downlink-prefix-ifaces "none"

iface "<Internet interface>" {
  pd
  option dns-server
  option domain
  option ntp-server
  option vendor-spec
}
```
 
## Normal setup flow

This section discusses the flow needed to fully set up the Internet connection
and have all the information necessary to bring up the SIP connection if
desired.

1. ICMPv6 Router Solicitation
   1. Receive MTU information from router (i.e., 1500 bytes; see section
      2.4.2.1.5 of [FLETS])
1. IPv4 DHCP exchange (NTT SIP network)
   1. Local address for use with SIP
   1. SIP server address
   1. Static route for SIP network
1. IPv6 DHCP exchange (Internet)
   * Request:
      1. Client ID must be of the DUID-LL (Link Layer) type (see section
         2.4.2.1.4 of [FLETS])
         * Format is `00:03:00:01:<6-byte MAC address>`
      1. Request should include Prefix Delegation (PD) (see section 2.4.2.1.2
         of [FLETS])
   * Response:
      1. Vendor-specific information (NTT):
         1. MAC address (option 201)
         1. Hikari denwa telephone number (option 202)
         1. SIP domain (option 204)
         1. Route information (option 210; not needed?)
      1. Identity Assocation for Prefix Delegation (IA-PD)
         * Sends a /56 network
         * Internal LAN address should be set to PD prefix in this format:  
           [1G type] `xxxx:xxxx:xxxx:xx00:1111:1111:1111:1111/64` (*not* on the interface
           it received the delegation from)  
           [10G type] `xxxx:xxxx:xxxx:xx00:yy:yyyy:yy00:0` (`yy:yyyy:yy` is the hexadecimal representation of your tunnel local IPv4 address)
1. IPv6 RADIUS exchange (IPv4-in-IPv6 setup)
   * Access-Request (1) packet:
      1. RADIUS Shared Secret and Password is needed
      1. Contains IA-PD prefix as username
         * Format is  
         [1G type] `xxxx:xxxx:xxxx:xx00:1111:1111:1111:1111`  
         [10G type] `xxxx:xxxx:xxxx:xx00`
      1. Must contain Vendor Specific Attributes (VSA)
         * MAC Address (1) NOTE: LAN side MAC address of HGW in 10G type.  
         * Client manufacturer (2)
         * Client software version (3)
         * Client hardware revision (4)
      1. CHAP authentication
         * Uses CHAP-Challenge (60) attribute
         * Password is shared among all clients
   * Access-Accept (2) packet:
      1. Contains Vendor Specific Attributes (VSA)
         * IPv4-in-IPv6 tunnel CPE local IPv4 address (204)
         * IPv4-in-IPv6 tunnel gateway IPv6 address (207)
      1. Other attributes don't appear to be useful
1. IPv6-in-IPv4 tunnel setup
   1. Use IPv4-in-IPv6 parameters discovered in IPv6 RADIUS exchange
   1. Must NOT have [Tunnel Encapsulation Limit Option][tunnel-encap]
      * Requires NetworkManager 1.12 or newer ([link to bug][nm-bug])

[FLETS]: https://flets.com/pdf/ip-int-flets-3.pdf "IP Network Service Interface for FLETS"
[tunnel-encap]: https://tools.ietf.org/html/rfc2473#page-13 "Tunnel Encapsulation Limit Option"
[nm-bug]: https://bugzilla.gnome.org/show_bug.cgi?id=791846 "NetworkManager bug"
