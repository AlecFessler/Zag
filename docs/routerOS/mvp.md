# RouterOS MVP: Home Router Replacement

This document defines the minimum viable feature set for Zag routerOS to replace a home router on a Google Fiber connection. The target setup:

```
Google Fiber ONT (WAN) ──► NIC port 0 ──► Zag routerOS ──► NIC port 1 ──► Dumb switch (LAN)
                                                │                              ├── PC
                                                │ (serial console)             ├── WAP(s)
                                                ▼                              └── other devices
                                           COM port
```

Each feature includes **why** it's needed and its current implementation status.

---

## 1. Layer 2: Link

### 1.1 Ethernet Frame Handling

**Status: Implemented** (`router/main.zig`, `router/util.zig`)

**What:** Parse and construct Ethernet II frames — read/write destination MAC, source MAC, and EtherType fields. Minimum frame size padding (60 bytes).

**Why:** Ethernet is the link-layer protocol on both the WAN (from the ONT) and LAN (to the switch) segments. Every packet the router touches arrives and departs as an Ethernet frame. The router must parse the EtherType to distinguish IPv4 (0x0800) from ARP (0x0806) and ignore everything else.

### 1.2 ARP (Address Resolution Protocol)

**Status: Implemented** (`router/arp.zig`)

**What:** Respond to ARP requests for the router's own IP. Send ARP requests to resolve next-hop MACs. Maintain a per-interface ARP cache (16 entries, 5-minute expiry).

**Why:** IP operates on logical addresses, but Ethernet needs physical MAC addresses. When the router needs to forward a packet to 192.168.1.100, it must know that host's MAC. ARP is the protocol that maps IPv4 addresses to MACs on a local Ethernet segment. Without ARP, the router cannot deliver a single frame.

**Limitations:** 16 entries per interface. If more than 16 LAN hosts are active simultaneously, the oldest entries get evicted. For a typical home network this is likely sufficient but may need to be increased for larger networks.

### 1.3 VLAN Tagging (802.1Q)

**Status: Not implemented**

**What:** Insert/strip 802.1Q VLAN tags on Ethernet frames. Route packets between VLANs.

**Why:** If the hardware NIC presents WAN and LAN as a single physical interface (common on embedded boards with a built-in switch chip), VLANs are how you logically separate the WAN and LAN traffic on the same wire. The ONT port would be tagged as VLAN 1, the LAN ports as VLAN 2, and the router strips/adds tags as it forwards.

**Note:** This may not be needed if the NIC has two physically separate ports with independent MAC addresses (which is the planned hardware setup). Evaluate once hardware is in hand.

---

## 2. Layer 3: Network

### 2.1 IPv4 Forwarding

**Status: Implemented** (`router/main.zig`, `router/iface.zig`)

**What:** Receive IPv4 packets on one interface, decrement TTL, recompute IP header checksum, and transmit on the other interface. Zero-copy path: modify headers in-place in the DMA buffer, then point the outbound NIC's TX descriptor at the inbound NIC's RX buffer.

**Why:** This is the core job of a router. Every packet from a LAN device destined for the internet (and every response coming back) must be forwarded between the WAN and LAN interfaces. TTL decrement prevents routing loops — if a packet has been forwarded too many times (TTL reaches 0), it's dropped.

### 2.2 NAT (Network Address Translation)

**Status: Implemented** (`router/nat.zig`)

**What:** Source NAT (masquerade) for outbound traffic — rewrite the LAN source IP/port to the WAN IP/port. Maintain a connection tracking table (256 entries) to reverse-translate inbound responses. Lock-free concurrent access with atomic CAS for inserts.

Supported protocols: TCP (with SYN/EST/FIN state tracking), UDP, ICMP.

Timeouts: TCP established 5min, TCP other 30s, UDP 2min, UDP DNS 30s, ICMP 60s.

**Why:** Google Fiber assigns one public IPv4 address. NAT lets all LAN devices share that single address. Without NAT, only one device could use the internet. The router rewrites outbound packets so they appear to come from the WAN IP, and uses the connection table to map inbound replies back to the correct LAN device.

**Limitations:** The table is a fixed-size hash table (256 entries). A home with heavy concurrent connections (many tabs, streaming, IoT) could potentially exhaust this. Also, the NAT port counter wraps around and doesn't check for port reuse conflicts.

### 2.3 ICMP Handling

**Status: Partially implemented** (`router/main.zig`, `router/ping.zig`)

**What currently works:**
- Echo reply: router responds to pings directed at its own IPs
- Echo request: router can ping other hosts (via console `ping` command)
- ICMP NAT: echo requests from LAN hosts are NATed and forwarded

**What's missing:**
- **TTL exceeded (Type 11):** When a forwarded packet's TTL reaches 0, the router should send an ICMP Time Exceeded message back to the sender. Currently, TTL=0 packets are silently dropped.
- **Destination unreachable (Type 3):** When the router receives a packet for a port/protocol it can't deliver, it should generate an ICMP Port Unreachable. This matters for traceroute and for applications that rely on ICMP feedback to detect failures.
- **Fragmentation needed (Type 3, Code 4):** When a packet is too large for the outbound MTU and DF (Don't Fragment) is set, the router should send this ICMP message. This is part of Path MTU Discovery.

**Why:** ICMP is the error-reporting and diagnostic protocol for IP. Ping verifies reachability. TTL exceeded messages make traceroute work. Unreachable messages tell senders to stop trying. Without proper ICMP generation, network debugging becomes much harder and some protocols (like PMTUD) break.

### 2.4 IP Fragmentation

**Status: Partially implemented** (`router/frag.zig`)

**What currently works:** Fragment tracking table (8 entries) for reassembly awareness.

**What's missing:** Full reassembly of fragmented packets destined for the router itself (e.g., a large DNS response). For forwarded traffic, the router shouldn't need to reassemble — just forward fragments individually (each carries the same IP ID and fragment offset).

**Why:** While most modern networks use Path MTU Discovery to avoid fragmentation, some edge cases still produce fragments (notably, certain DNS responses over UDP that exceed 512 bytes but the server doesn't support EDNS0). The router needs to at least forward fragments correctly and reassemble packets addressed to itself.

### 2.5 MTU Handling

**Status: Not implemented**

**What:** Respect the MTU of each interface. If a packet exceeds the outbound MTU and DF is set, drop it and send ICMP Fragmentation Needed. If DF is not set, fragment the packet.

**Why:** Google Fiber's MTU is typically 1500 bytes (standard Ethernet), so this rarely triggers. However, if any tunnel or encapsulation is ever added, or if a LAN device sends jumbo frames, MTU enforcement prevents silent packet drops. It's also essential for Path MTU Discovery to work correctly.

### 2.6 TCP MSS Clamping

**Status: Not implemented**

**What:** On TCP SYN and SYN-ACK packets traversing the router, rewrite the MSS (Maximum Segment Size) TCP option to be no larger than (interface MTU - 40). This prevents TCP connections from trying to send packets that would need to be fragmented.

**Why:** This is a practical workaround for Path MTU black holes. Some ISPs or paths have broken PMTUD (firewalls that block ICMP Fragmentation Needed). MSS clamping ensures TCP connections never try to send segments larger than the link can handle. Most production routers do this unconditionally. For a Google Fiber connection with 1500 MTU, the clamped MSS would be 1460.

### 2.7 Default Gateway / Routing Table

**Status: Partially implemented** (hardcoded gateway in `router/nat.zig`)

**What currently works:** The WAN gateway is hardcoded to 10.0.2.1 (QEMU tap). All non-LAN traffic is forwarded to this address.

**What's needed:** Use the gateway IP learned from the WAN DHCP lease (option 3, Router). The DHCP client already parses the offer but doesn't extract the gateway option. On real hardware, the gateway will be the ONT's address (assigned by Google Fiber).

**Why:** The default gateway is where the router sends all traffic that isn't destined for a directly-connected network. Getting this from DHCP is how every home router learns its upstream gateway.

### 2.8 IPv6

**Status: Not implemented**

**What:** Full IPv6 stack: Neighbor Discovery Protocol (NDP, replaces ARP), Router Advertisement/Solicitation, DHCPv6 or SLAAC for address assignment, IPv6 forwarding, IPv6 firewall.

**Why:** Google Fiber provides a /56 IPv6 prefix via DHCPv6 prefix delegation. Many modern services (Google, Facebook, Netflix, Apple) prefer IPv6. Some devices and applications work better or only work over IPv6. Without IPv6 support, the router would be IPv4-only, which is functional but leaves performance and capability on the table.

**Note:** This is the single largest missing feature. It's an entire parallel network stack. For a true MVP, the router can function without it (IPv4 NAT handles everything), but it should be a high-priority follow-up. Consider implementing in phases: first NDP + static addressing, then SLAAC for LAN, then DHCPv6-PD for WAN.

---

## 3. Layer 4: Transport

### 3.1 TCP Connection Tracking

**Status: Implemented** (`router/nat.zig`)

**What:** Track TCP connection state through the NAT table: SYN_SENT → ESTABLISHED → FIN_WAIT. Different timeouts per state (SYN 30s, established 5min, FIN 30s).

**Why:** Stateful tracking lets the router know when a connection is finished and can clean up the NAT entry. Without it, NAT entries would either leak (never cleaned up) or be cleaned up too aggressively (killing active connections). The state machine also allows the firewall to distinguish new connections from established ones.

### 3.2 UDP Tracking

**Status: Implemented** (`router/nat.zig`)

**What:** Track UDP "connections" (really just source/dest pairs) with 2-minute timeout (30s for DNS).

**Why:** UDP is stateless but NAT still needs to remember the mapping so replies come back to the right LAN host. The shorter DNS timeout reflects that DNS queries are typically answered in milliseconds.

---

## 4. Services

### 4.1 DHCP Server (LAN)

**Status: Implemented** (`router/dhcp_server.zig`)

**What:** Allocate IP addresses to LAN devices. Responds to DISCOVER with OFFER, REQUEST with ACK. Provides: IP address (192.168.1.100+), subnet mask (255.255.255.0), gateway (router LAN IP), DNS server (router LAN IP), lease time (7200s).

**Why:** Without DHCP, every device on the LAN would need a manually configured static IP. DHCP automates this: when a phone, laptop, or IoT device connects to the network, it broadcasts a DHCP request and the router assigns it an IP, tells it the default gateway and DNS server. This is what makes "plug in and it works" possible.

**Limitations:**
- **No lease expiry/renewal:** Leases are permanent — once assigned, never reclaimed. If devices come and go (guests, IoT), the pool (32 entries, starting at .100) will eventually be exhausted. Need to add lease duration tracking, T1/T2 renewal timers, and expiry.
- **No hostname tracking (option 12):** Devices send their hostname in DHCP requests. Storing this would allow the console to show friendly names instead of just MACs.
- **No static/reserved leases:** Can't pin a specific IP to a specific MAC (useful for servers, printers, etc. that you want at a stable address).
- **Hardcoded subnet:** 192.168.1.0/24 with addresses starting at .100. Not configurable.

### 4.2 DHCP Client (WAN)

**Status: Implemented** (`router/dhcp_client.zig`)

**What:** Obtain the WAN IP address from the ISP via DHCP. Implements the full DORA sequence (Discover → Offer → Request → Ack). Learns upstream DNS from option 6. 10-second retry on timeout.

**Why:** The ISP (Google Fiber, via the ONT) assigns the router's public IP address through DHCP. Without a DHCP client, the router wouldn't know what public IP to use for NAT, and wouldn't know the upstream DNS server.

**Limitations:**
- **No lease renewal:** Once bound, the client never renews. Real DHCP leases expire (typically 24-48 hours). The client should send a REQUEST at T1 (50% of lease time) to renew, and rebind at T2 (87.5%) if renewal fails.
- **No gateway extraction (option 3):** The default gateway is hardcoded rather than learned from the DHCP response.
- **No release on shutdown:** When the router shuts down, it should send a DHCP RELEASE to free the IP.

### 4.3 DNS Relay

**Status: Implemented** (`router/dns.zig`)

**What:** Intercept DNS queries (UDP port 53) from LAN clients, rewrite the query ID, forward to the upstream DNS server via the WAN interface, then translate the response ID back and deliver to the LAN client. 32 concurrent query slots, oldest evicted when full.

**Why:** LAN devices are told (via DHCP) that the router is their DNS server. The router doesn't actually resolve names — it relays queries to the upstream server (learned from WAN DHCP, default 10.0.2.1). This is simpler than running a full resolver but achieves the same result from the client's perspective. It also means DNS works transparently: clients just point at the router and it handles the rest.

**Limitations:**
- **No caching:** Every query is forwarded upstream, even repeat lookups for the same name. A DNS cache would significantly reduce latency for repeated queries (e.g., CDN hostnames that every device hits).
- **UDP only:** DNS over TCP (for large responses) is not handled. This rarely matters for typical home use but can affect DNSSEC validation.
- **No EDNS0 support:** Extended DNS options aren't parsed or forwarded specially.

### 4.4 Firewall

**Status: Implemented** (`router/firewall.zig`)

**What:** Block list: up to 32 rules matching source IP (with mask), optional protocol and port. Default policy is allow. Rules checked on WAN inbound traffic.

Port forwarding: up to 16 DNAT rules mapping WAN port to LAN IP:port. TCP checksums adjusted via RFC 1624 incremental update.

**Why:** The firewall protects LAN devices from unsolicited inbound traffic. Without it, any host on the internet could probe or connect to LAN devices. NAT provides implicit protection (unsolicited inbound packets don't match any NAT entry and are dropped), but explicit firewall rules add defense-in-depth and allow blocking specific sources.

Port forwarding is the reverse: it allows specific services on LAN devices to be reachable from the internet (e.g., a game server, SSH, a web server).

**Limitations:**
- **No stateful inspection beyond NAT:** The firewall rules are simple IP/port matches. There's no concept of "allow established connections" independent of NAT — that's handled implicitly by the NAT table.
- **WAN-only:** Rules only apply to WAN inbound. No LAN-to-LAN or outbound filtering.
- **No logging:** Blocked packets are silently dropped with no record.
- **Rules are volatile:** Lost on reboot.

---

## 5. Infrastructure

### 5.1 NIC Driver

**Status: Implemented for QEMU** (`router/e1000.zig`)

**What:** Intel e1000e driver: reset, link-up, RX/TX descriptor ring setup, DMA, bus master enable, MAC address read, polled RX, zero-copy TX (point descriptor at other NIC's RX buffer), local TX (copy to TX buffer).

**Why:** The NIC driver is how the router talks to the network hardware. Everything else (routing, NAT, DHCP, etc.) depends on being able to send and receive Ethernet frames.

**What's needed:** A driver for the actual hardware NIC. Common choices for x86 router boards:
- **Intel i210/i211/i225/i226** — Still e1000-family register-compatible in many ways, may need minor driver adjustments
- **Realtek RTL8111/8125** — Common on consumer boards, completely different register set
- **Intel X710/XL710** — 10GbE, if going high-performance

The e1000e driver structure (init, poll RX, program TX, read MAC) is a good template. The real driver will need the same interface but different register offsets and initialization sequences.

### 5.2 DMA and Zero-Copy Forwarding

**Status: Implemented** (`router/dma.zig`, `router/iface.zig`)

**What:** Single shared DMA region mapped to both NICs. RX buffers from one NIC are used directly as TX data for the other NIC by programming the TX descriptor with the RX buffer's DMA address. Buffer state tracking (free / sw_owned / tx_pending) and reclaim logic.

**Why:** Zero-copy forwarding is a performance optimization: the most common operation (forward a packet from WAN to LAN or vice versa) avoids any memcpy. The CPU only touches the packet headers (for NAT/checksum rewrite) and the descriptor rings. This keeps cache pressure low and throughput high.

### 5.3 Serial Console

**Status: Implemented** (`serial_driver/main.zig`, `console/main.zig`)

**What:** 16550 UART driver with TX/RX buffering. Interactive TUI with line editing, command parsing, and response display. Full command set for monitoring and configuration.

**Why:** On a headless router box with no display, the serial console is the primary management interface. Plugging in a USB-to-serial cable and opening a terminal gives full visibility into the router's state: interface status, ARP/NAT/DHCP tables, firewall rules, packet counters, and the ability to configure settings.

### 5.4 NFS Client

**Status: Implemented** (`nfs_client/`)

**What:** NFSv3 over UDP with AUTH_UNIX. Operations: mount, ls (READDIR), cat (LOOKUP+READ), put (CREATE+WRITE+COMMIT), mkdir (MKDIR), rm (REMOVE). Communicates with the router via SHM channel for UDP transport.

**Why:** Primarily a development and diagnostic tool. Allows the router to read/write files on a network server, which is useful for loading configuration, dumping logs, or transferring data without needing a local filesystem.

### 5.5 Persistent Configuration

**Status: Not implemented**

**What:** Save router configuration (firewall rules, port forwards, DHCP static leases, upstream DNS) to non-volatile storage and restore on boot.

**Why:** Currently every setting is lost on reboot. On real hardware, you'd configure port forwards, firewall rules, etc. once and expect them to persist. Options:
- Store config on an NFS share (already have the client)
- Store on a small local filesystem (USB, SPI flash)
- Store in UEFI variables

### 5.6 Watchdog / Self-Healing

**Status: Not implemented**

**What:** Monitor the router's own health: are both NICs still link-up? Is the WAN DHCP lease still valid? Are the RX/TX descriptor rings progressing or stuck? If something is wrong, attempt recovery (re-init the NIC, re-run DHCP, restart the router process).

**Why:** A home router must be reliable. If the e1000e gets into a bad state (hung TX ring, etc.), the router needs to detect this and recover without human intervention. Users expect to never touch the router — it should just work.

### 5.7 NTP Client

**Status: Implemented** (`ntp_client/main.zig`)

**What:** SNTPv4 client that obtains wall-clock time from an NTP server. Runs as a standalone process communicating with the router via SHM channel for UDP transport. Auto-syncs on startup, supports manual sync via console. Console commands: `time` (show current time), `sync` (trigger NTP sync), `ntpserver <ip>` (change server).

**Why:** The router currently uses monotonic nanosecond timestamps from the CPU (via `rdtsc` or similar). These are fine for relative timing (lease expiry, NAT timeout) but don't provide wall-clock time for:
- Log timestamps (when did this event happen?)
- DHCP lease absolute expiry times
- Certificate validation (if TLS is ever added)

An NTP client is simple (single UDP request/response) and provides millisecond-accurate time.

### 5.8 Logging

**Status: Minimal** (serial `write` calls in router code)

**What:** Structured logging of router events: DHCP leases granted/expired, NAT table full, firewall blocks, link state changes, errors.

**Why:** When something goes wrong ("the internet stopped working"), logs are the first place to look. Currently the only output is a few hardcoded serial messages during init. A logging system that captures events with timestamps and severity would make debugging much faster. Logs could be viewed over the serial console and optionally sent to the NFS server.

---

## 6. Nice-to-Have (Post-MVP)

These features would improve the router but aren't strictly required for basic home internet:

### 6.1 DNS Cache

**What:** Cache DNS responses (respecting TTL) so repeated queries are answered locally.

**Why:** Reduces latency by ~30-100ms for cached lookups. Most home traffic hits the same few dozen domains repeatedly.

### 6.2 UPnP / NAT-PMP / PCP

**What:** Allow LAN applications to automatically request port forwards.

**Why:** Game consoles (Xbox, PlayStation), voice/video chat (Discord, FaceTime), and P2P applications need inbound connections. Without UPnP, users must manually configure port forwards. Most consumer routers support UPnP.

### 6.3 mDNS Relay

**What:** Relay multicast DNS (224.0.0.251, port 5353) between network segments if needed.

**Why:** mDNS enables zero-configuration service discovery (AirPlay, Chromecast, printers). Since all devices are on the same LAN segment behind a dumb switch, mDNS should work without relay. But if VLANs are ever introduced (IoT isolation), mDNS relay becomes necessary.

### 6.4 Traffic Shaping / QoS

**What:** Prioritize certain traffic (VoIP, gaming) over bulk transfers.

**Why:** Prevents a large download from making video calls choppy. Typically done with queuing disciplines (fq_codel, etc.) on the outbound interface.

### 6.5 Bandwidth Monitoring

**What:** Per-device traffic statistics: which LAN host is using how much bandwidth.

**Why:** Useful for identifying bandwidth hogs, diagnosing slowness, and general network awareness.

### 6.6 SSH Server

**What:** Remote management over the network instead of requiring a physical serial cable.

**Why:** Convenience. Once the router is deployed, you may not always have physical access to the serial port. SSH would allow remote configuration changes.

---

## 7. Summary Matrix

| # | Feature | Status | MVP? | Effort |
|---|---------|--------|------|--------|
| 1.1 | Ethernet frames | Done | Yes | — |
| 1.2 | ARP | Done | Yes | — |
| 1.3 | VLAN (802.1Q) | Not started | Maybe | Medium |
| 2.1 | IPv4 forwarding | Done | Yes | — |
| 2.2 | NAT | Done | Yes | — |
| 2.3 | ICMP (echo) | Done | Yes | — |
| 2.3 | ICMP (TTL exceeded, unreachable) | Not started | Yes | Small |
| 2.4 | IP fragmentation | Partial | No | Small |
| 2.5 | MTU handling | Not started | No | Small |
| 2.6 | TCP MSS clamping | Not started | Yes | Small |
| 2.7 | Default gateway from DHCP | Partial | Yes | Small |
| 2.8 | IPv6 | Not started | No* | Large |
| 3.1 | TCP connection tracking | Done | Yes | — |
| 3.2 | UDP tracking | Done | Yes | — |
| 4.1 | DHCP server (basic) | Done | Yes | — |
| 4.1 | DHCP lease expiry/renewal | Not started | Yes | Small |
| 4.1 | DHCP static leases | Not started | No | Small |
| 4.2 | DHCP client (basic) | Done | Yes | — |
| 4.2 | DHCP client lease renewal | Not started | Yes | Small |
| 4.2 | DHCP client gateway option | Not started | Yes | Small |
| 4.3 | DNS relay | Done | Yes | — |
| 4.3 | DNS cache | Not started | No | Medium |
| 4.4 | Firewall | Done | Yes | — |
| 5.1 | NIC driver (e1000e) | Done | Yes | — |
| 5.1 | NIC driver (real hardware) | Not started | Yes | Medium-Large |
| 5.2 | Zero-copy DMA | Done | Yes | — |
| 5.3 | Serial console | Done | Yes | — |
| 5.4 | NFS client | Done | No | — |
| 5.5 | Persistent config | Not started | Yes | Medium |
| 5.6 | Watchdog | Not started | Yes | Medium |
| 5.7 | NTP client | Done | No | — |
| 5.8 | Logging | Minimal | Yes | Small |

\* IPv6 is not strictly required for MVP since IPv4 NAT handles all traffic, but it's high priority for a complete deployment.

---

## 8. Recommended Implementation Order

Prioritized by "what blocks real-hardware deployment":

1. **DHCP client: extract gateway (option 3)** — Tiny change, removes hardcoded gateway
2. **DHCP lease expiry** — Without this, the server pool exhausts over days/weeks
3. **DHCP client renewal** — Without this, WAN IP is lost when ISP lease expires
4. **ICMP TTL exceeded / unreachable** — Makes traceroute work, helps debugging
5. **TCP MSS clamping** — Prevents mysterious connection failures
6. **Logging** — Need visibility before deploying on real hardware
7. **Watchdog** — Must self-recover from NIC hangs
8. **Real NIC driver** — Required for actual hardware
9. **Persistent config** — Required for unattended operation
10. **IPv6** — Required for full Google Fiber experience
