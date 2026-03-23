# RouterOS Console Reference

Interactive command-line interface over the serial port for monitoring and configuring the router.

---

## Commands

| Command | Description |
|---------|-------------|
| `help` | List available commands |
| `status` | Show interface IPs and MACs |
| `ping <ip>` | Ping an IP address (4 packets) |
| `arp` | Show ARP tables (WAN + LAN) |
| `nat` | Show NAT connection tracking table |
| `leases` | Show DHCP lease table |
| `ifstat` | Show per-interface RX/TX/drop counters |
| `rules` | Show firewall block rules + port forwards |
| `block <ip>` | Block an IP on the WAN interface |
| `allow <ip>` | Remove a block rule for an IP |
| `forward <tcp\|udp> <wport> <lip> <lport>` | Port forward WAN port to LAN IP:port |
| `dns <ip>` | Set upstream DNS server IP |
| `dhcp-client` | Start WAN DHCP client or show lease status |
| `version` | Show system version |
| `uptime` | Show time since boot |
| `clear` | Clear terminal |

---

## ping

```
> ping 10.0.2.1
reply from 10.0.2.1: seq=0 time=201us
reply from 10.0.2.1: seq=1 time=643us
reply from 10.0.2.1: seq=2 time=661us
reply from 10.0.2.1: seq=3 time=667us
--- ping 10.0.2.1: 4 sent, 4 received ---
```

Auto-selects interface: LAN subnet (192.168.1.0/24) via LAN, all others via WAN. 3-second timeout per packet.

---

## ifstat

```
> ifstat
WAN: rx=8 (708B) tx=3 (256B) drop=0
LAN: rx=3 (180B) tx=3 (180B) drop=0
```

---

## Firewall

```
> block 10.0.2.99
firewall: block rule added

> allow 10.0.2.99
firewall: rule removed
```

Block rules apply to incoming WAN traffic. Blocked packets counted in `ifstat` drop counter. Up to 32 rules.

---

## Port Forwarding

```
> forward tcp 80 192.168.1.100 8080
forward: rule added
```

Forwards WAN TCP/UDP port to LAN IP:port. TCP checksums adjusted incrementally (RFC 1624). Up to 16 rules.

---

## DNS Relay

```
> dns 8.8.8.8
DNS upstream set to 8.8.8.8
```

Relays DNS queries (UDP 53) from LAN clients to the configured upstream. Default: 10.0.2.1. Updated automatically by DHCP client if option 6 is received. Up to 32 concurrent queries tracked.

---

## DHCP Client (WAN)

```
> dhcp-client
DHCP client: discovering...

> dhcp-client
DHCP client: bound to 10.0.2.15 (server 10.0.2.2)
```

Starts DHCP on the WAN interface. The router sends DISCOVER, processes OFFER, sends REQUEST, and applies the ACK'd IP. Also learns upstream DNS from option 6. Retries on 10-second timeout.

---

## NAT Table

```
> nat
tcp 192.168.1.100:49152 -> 10.0.2.1:80 (wan:10001)
icmp 192.168.1.100:1234 -> 10.0.2.1:0 (wan:10000)
--- 2 NAT entries ---
```

Shows protocol, LAN source, destination, and translated WAN port. TCP entries track connection state (SYN/EST/FIN) with per-state timeouts:

| Protocol | State | Timeout |
|----------|-------|---------|
| ICMP | — | 60s |
| UDP (general) | — | 120s |
| UDP (DNS, port 53) | — | 30s |
| TCP | SYN sent | 30s |
| TCP | Established | 300s |
| TCP | FIN/RST | 30s |

---

## ARP Table

```
> arp
WAN ARP:
  10.0.2.1 -> e6:11:e1:e5:b6:b9
LAN ARP:
  192.168.1.100 -> 3a:26:f0:f3:db:fc
--- 2 entries ---
```

16 entries per interface. Entries expire after 5 minutes of inactivity.

---

## Line Editing

- **Backspace** (127/8): delete character
- **Enter** (CR/LF): execute command
- Printable ASCII (32-126): echo and append
- Max line length: 128 characters
