# sbradclient
Setup utility for a certain BB in Japan.  
Original repo: https://github.com/kruton/sofutobanku
 
## Normal setup flow

1. ICMPv6 Router Solicitation
   1. Receive MTU information from router (i.e., 1500 bytes; see section
      2.4.2.1.5 of [FLETS])
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
         1. Hikari Denwa telephone number (option 202)
         1. SIP domain (option 204)
         1. Route information (option 210; not needed?)
      1. Identity Assocation for Prefix Delegation (IA-PD)
         * Sends a /64 address (/56 PD prefix if Hikari Denwa is available or CROSS type)
         * A certain network interface must add an address like this:  
           [NEXT] `xxxx:xxxx:xxxx:xx00:1111:1111:1111:1111/64` (*not* on the interface
           it received the delegation from)  
           [CROSS] `xxxx:xxxx:xxxx:xx00:yy:yyyy:yy00:0` (`yy:yyyy:yy` is the hex format of tunnel local IPv4 address)
1. IPv6 RADIUS exchange (IPv4-over-IPv6 setup)
   * Access-Request (1) packet:
      1. RADIUS Shared Secret and Password is needed
      1. Contains a special IPv6 address as username
         * Format is  
         [NEXT] `xxxx:xxxx:xxxx:xx00:1111:1111:1111:1111`  
         [CROSS] `xxxx:xxxx:xxxx:xx00`
      1. Must contain Vendor Specific Attributes (VSA)
         * CPE MAC address (1) 
         * CPE vendor name (2)
         * CPE product name (3)
         * CPE hardware version (4)  
         NOTE: *In CROSS type, CPE MAC address must be the LAN side MAC of HGW and all of VSA must be in the same AVP.*
      1. CHAP authentication
         * Uses CHAP-Challenge (60) attribute
         * Password and secret are shared.
   * Access-Accept (2) packet:
      1. Contains Vendor Specific Attributes (VSA)
         * CPE WAN IPv4 address (204)
         * IPv6 gateway address (207)
      1. Other attributes don't appear to be useful
1. IPv4-over-IPv6 tunnel setup
   1. Use parameters discovered in IPv6 RADIUS exchange
   1. Must NOT have [Tunnel Encapsulation Limit Option][tunnel-encap]

[FLETS]: https://flets.com/pdf/ip-int-flets-3.pdf "IP Network Service Interface for FLETS"
[tunnel-encap]: https://tools.ietf.org/html/rfc2473#page-13 "Tunnel Encapsulation Limit Option"
