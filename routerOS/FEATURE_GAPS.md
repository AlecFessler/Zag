# RouterOS Feature Gap Analysis

What's already implemented and working: IPv4/IPv6 dual-stack forwarding, NAT with TCP state tracking, firewall with port forwarding, DHCP server & client (including static leases), DHCPv6 prefix delegation, DNS relay & caching, ARP/NDP, SLAAC, ICMP/ICMPv6 (ping, traceroute), IP fragmentation tracking, TCP MSS clamping, HTTP management API, serial console CLI, NTP, NFS client, UDP forwarding, UPnP IGD, PCP (Port Control Protocol), persistent configuration across reboots.

---

## Core Features Missing

These are features that many home networks depend on. Missing any of these could cause noticeable breakage or incompatibility depending on your ISP and the devices on your LAN.

### 1. Static Routes

**What it is:** The ability to manually add routing table entries that direct traffic for specific destination subnets to specific next-hop gateways.

**Why you'd want it:** If you ever run a VPN server, have multiple subnets (e.g., a guest network on a different VLAN), or have a secondary router/AP doing its own routing, you need static routes. Without them, the router only knows about its directly-connected WAN and LAN subnets and has no way to reach anything else except via the default gateway. For a single-subnet home setup this works, but the moment you add any network complexity you'll need this.

### 2. PPPoE Client

**What it is:** Point-to-Point Protocol over Ethernet — a connection protocol some ISPs require you to use to authenticate and establish your WAN connection. Instead of plain DHCP on the WAN interface, you encapsulate traffic in PPP frames with a username/password.

**Why you'd want it:** Some ISPs (particularly DSL, fiber-to-the-home in certain regions, and some cable providers) require PPPoE authentication. If your ISP is one of them, the router literally cannot get online without it — DHCP on WAN won't work. AT&T Fiber, CenturyLink, and many European/Asian ISPs use PPPoE. If your ISP uses plain DHCP, you can skip this entirely.

### 3. VLAN Support (802.1Q)

**What it is:** Virtual LAN tagging — the ability to tag Ethernet frames with a VLAN ID so a single physical NIC can carry traffic for multiple isolated networks. The router would need to parse VLAN tags on ingress and add them on egress.

**Why you'd want it:** VLANs let you segment your network without extra hardware. Common uses: isolating IoT devices (smart bulbs, cameras) from your main network so a compromised device can't reach your computers; creating a guest WiFi network that can reach the internet but not your LAN; separating a home lab. Most managed switches and WiFi access points support VLANs. Without VLAN support in the router, you can't do any network segmentation — everything is one flat subnet.

---

## Nice-to-Haves

These aren't strictly necessary for basic routing, but they're features you'll likely miss if you're used to a consumer router or running something like OpenWrt.

### 4. mDNS/DNS-SD Relay (Multicast DNS)

**What it is:** mDNS (multicast DNS, port 5353) is how devices advertise and discover services on the local network without a central DNS server. Devices broadcast `.local` names and service records. A relay/reflector forwards these between subnets or VLANs.

**Why you'd want it:** Chromecast, AirPlay, AirPrint, Spotify Connect, HomeKit, and many other discovery-based protocols all use mDNS. On a single flat LAN it works without any router involvement (it's pure multicast). But the moment you add VLANs or subnets, mDNS stops working across them because multicast is link-local. If you implement VLANs, you'll almost certainly need an mDNS relay or your Chromecast will "disappear" from your phone. If you stay on a single subnet, you can skip this.

### 5. IGMP Proxy / Snooping

**What it is:** IGMP (Internet Group Management Protocol) manages multicast group membership. IGMP snooping lets the router track which LAN devices want to receive which multicast streams. IGMP proxy forwards multicast subscriptions between WAN and LAN.

**Why you'd want it:** IPTV services (if your ISP offers them) are delivered via multicast. Without IGMP proxy, the multicast streams from WAN won't reach your LAN devices. Even without IPTV, IGMP snooping prevents multicast traffic (like mDNS, SSDP/UPnP discovery) from flooding every port — instead it only goes to devices that asked for it. On a small home network this is mostly an optimization, but for IPTV it's essential.

### 6. QoS / Traffic Shaping

**What it is:** Quality of Service — the ability to prioritize certain types of traffic over others. Typically implemented as a packet scheduler that can rate-limit, prioritize, or queue packets based on protocol, port, IP, or DSCP markings.

**Why you'd want it:** When your upload bandwidth is saturated (someone uploading a large file, a backup running), it can starve latency-sensitive traffic like video calls, gaming, and even basic web browsing. QoS lets you guarantee that interactive traffic gets priority. The classic scenario: someone starts a big upload and everyone else's internet "feels slow" even though download bandwidth is fine. With traffic shaping (specifically SQM/fq_codel style), you can eliminate bufferbloat. This is one of the main reasons people run custom router firmware.

### 7. Dynamic DNS (DDNS)

**What it is:** A client that automatically updates a DNS record (e.g., `myhouse.duckdns.org`) whenever your WAN IP changes, so you can always reach your home network by hostname.

**Why you'd want it:** If you run any services accessible from outside your network (VPN, game server, security camera access, SSH), you need a stable way to reach your home IP. Most residential ISPs give you a dynamic IP that changes periodically. Without DDNS, every time your IP changes you lose remote access until you manually figure out your new IP. With DDNS, a small client detects the change and updates the DNS record automatically.

### 8. DNS over TLS (DoT) or DNS over HTTPS (DoH)

**What it is:** Encrypting DNS queries between your router and the upstream DNS resolver. Standard DNS (port 53) is plaintext — anyone on the path (your ISP, network taps) can see every domain you look up. DoT (port 853) wraps DNS in TLS. DoH wraps it in HTTPS.

**Why you'd want it:** Privacy. Your ISP can see every domain your household queries, and some ISPs sell this data or use it for ad targeting. DoT/DoH prevents this. It also prevents DNS hijacking/manipulation by middleboxes. The practical blocker here is that you'd need a TLS implementation, which is a significant amount of code for a bare-metal OS. This might be more realistic as a longer-term goal.

### 9. Wake-on-LAN (WoL) Forwarding

**What it is:** Wake-on-LAN uses a "magic packet" (a UDP broadcast containing a target MAC address repeated 16 times) to wake a sleeping/powered-off computer via its network card.

**Why you'd want it:** If you want to remotely wake a computer on your LAN (e.g., wake your desktop from your phone, or from outside the network via a port forward), the router needs to either forward the WoL broadcast or provide an API endpoint that generates and sends the magic packet. This is a small feature but very handy if you use it.

### 10. DNS Rebinding Protection

**What it is:** Inspecting DNS responses and blocking any response from an external DNS server that resolves to a private/internal IP address (10.x, 192.168.x, etc.).

**Why you'd want it:** DNS rebinding is an attack where a malicious website's DNS record initially points to a public IP, then switches to a private IP. The browser's same-origin policy doesn't catch it because the domain hasn't changed, so the attacker's JavaScript can now make requests to devices on your LAN (routers, NAS, IoT devices). Most of these devices have weak or no authentication on their local web interfaces. Blocking private IPs in external DNS responses is a simple, effective mitigation. This is a small check in the DNS relay path.

### 11. Hairpin NAT (NAT Loopback)

**What it is:** When a device on your LAN tries to access your own public/WAN IP (or a port-forwarded service), the router recognizes it and routes the traffic internally instead of sending it out the WAN and back.

**Why you'd want it:** Without hairpin NAT, if you set up a port forward to a server on your LAN and then try to access it from another LAN device using your public IP, it won't work. The traffic goes out to the WAN, comes back, and the router doesn't know to redirect it internally. This is a common source of "it works from outside but not inside" confusion. Most consumer routers handle this transparently.

---

## Current Limitations Worth Noting

These are areas where existing features work but have constraints that may matter in practice.

### 12. Single-Connection TCP Stack

The TCP stack (`tcp_stack.zig`) only handles one connection at a time on port 80. If two devices try to load the management web UI simultaneously, one will be rejected. For a management interface this is usually fine (you're rarely configuring from two devices at once), but it's worth knowing.

### 13. HTTP/1.0, No TLS

The management interface is HTTP/1.0 over plaintext port 80. There's no HTTPS. This means management credentials (if you add authentication) would be sent in cleartext. On a LAN this is low risk, but if you ever expose management remotely it's a problem. Adding TLS requires a crypto library, which is a major effort on bare metal.

### 14. DNS Cache Size (64 Entries)

The DNS cache holds 64 entries. A typical household with a few active devices could easily have more than 64 unique domains in flight, meaning cache eviction will be frequent and you'll see more upstream queries than expected. Bumping this to 256-512 would be a simple change with meaningful improvement.

### 15. No Management Authentication

The HTTP API and console have no authentication. Anyone on the LAN can access the management interface and modify firewall rules, port forwards, etc. For a home network where you trust all LAN devices this is acceptable, but it means a compromised IoT device could reconfigure your router.

### 16. IPv6 NAT66 Not Implemented

Your IPv6 setup does prefix delegation and SLAAC, which is the correct approach — IPv6 is designed to avoid NAT. This is listed just for awareness: if your ISP doesn't provide a delegated prefix (rare but possible), you'd need NAT66 as a workaround. Most ISPs that offer IPv6 do provide PD, so this likely won't be an issue.
