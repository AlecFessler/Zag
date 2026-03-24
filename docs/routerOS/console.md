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

### NFS Commands

| Command | Description |
|---------|-------------|
| `mount` | Mount NFS export |
| `ls [path]` | List directory |
| `cat <path>` | Read file |
| `put <path>` | Write file (end with empty line) |
| `mkdir <path>` | Create directory |
| `rm <path>` | Remove file |

### NTP Commands

| Command | Description |
|---------|-------------|
| `time` | Show current UTC time |
| `sync` | Sync time via NTP |
| `ntpserver <ip>` | Set NTP server IP |

---

## status

```
> status
WAN: 10.0.2.15 mac=52:54:00:12:34:56
LAN: 192.168.1.1 mac=52:54:00:12:34:57
```

---

## ping

```
> ping 10.0.2.1
reply from 10.0.2.1: seq=0 time=81us
reply from 10.0.2.1: seq=1 time=625us
reply from 10.0.2.1: seq=2 time=131us
reply from 10.0.2.1: seq=3 time=629us
--- ping 10.0.2.1: 4 sent, 4 received ---
```

Auto-selects interface: LAN subnet (192.168.1.0/24) via LAN, all others via WAN. 3-second timeout per packet.

---

## ifstat

```
> ifstat
WAN rx=4 tx=3 drop=0
LAN rx=0 tx=0 drop=0
```

---

## Firewall

```
> block 1.2.3.4
OK

> rules
block 1.2.3.4
---

> allow 1.2.3.4
OK
```

Block rules apply to incoming WAN traffic. Up to 32 rules.

---

## Port Forwarding

```
> forward tcp 8080 192.168.1.100 80
OK

> rules
forward tcp :8080 -> 192.168.1.100:80
---
```

Forwards WAN TCP/UDP port to LAN IP:port. TCP checksums adjusted incrementally (RFC 1624). Up to 16 rules.

---

## DNS Relay

```
> dns 8.8.8.8
OK
```

Relays DNS queries (UDP 53) from LAN clients to the configured upstream. Default: 10.0.2.1. Updated automatically by DHCP client if option 6 is received. Up to 32 concurrent queries tracked.

---

## DHCP Client (WAN)

```
> dhcp-client
DHCP client: idle -> discovering
```

Starts DHCP on the WAN interface. The router sends DISCOVER, processes OFFER, sends REQUEST, and applies the ACK'd IP. Also learns upstream DNS from option 6. Retries on 10-second timeout.

---

## NAT Table

```
> nat
tcp 192.168.1.100:49152 -> :10001 -> 10.0.2.1:80
udp 192.168.1.100:1234 -> :10000 -> 10.0.2.1:53
---
```

Shows protocol, LAN source, translated WAN port, and destination. TCP entries track connection state (SYN/EST/FIN) with per-state timeouts:

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
WAN 10.0.2.1 e6:11:e1:e5:b6:b9
---
```

16 entries per interface. Entries expire after 5 minutes of inactivity.

---

## DHCP Leases

```
> leases
192.168.1.100 aa:bb:cc:dd:ee:ff
---
```

Shows IP and MAC for each active DHCP lease. Up to 32 leases.

---

## Line Editing

- **Backspace** (127/8): delete character
- **Enter** (CR/LF): execute command
- Printable ASCII (32-126): echo and append
- Max line length: 128 characters
