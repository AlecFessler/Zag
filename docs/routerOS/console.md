# RouterOS Console Reference

The RouterOS console provides an interactive command-line interface over the serial port for monitoring and configuring the router.

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
| `version` | Show system version |
| `uptime` | Show time since boot |
| `clear` | Clear terminal |

---

## ping

```
> ping 10.0.2.1
reply from 10.0.2.1: seq=0 time=182us
reply from 10.0.2.1: seq=1 time=617us
reply from 10.0.2.1: seq=2 time=652us
reply from 10.0.2.1: seq=3 time=710us
--- ping 10.0.2.1: 4 sent, 4 received ---
```

Auto-selects interface: LAN subnet (192.168.1.0/24) via LAN, all others via WAN. 3-second timeout per packet. ARP resolution happens automatically.

---

## ifstat

```
> ifstat
WAN: rx=8 (708B) tx=3 (256B) drop=0
LAN: rx=3 (256B) tx=3 (256B) drop=0
```

Counters track all packets processed by the router (after NIC driver bridging).

---

## Firewall

```
> block 10.0.2.99
firewall: block rule added

> allow 10.0.2.99
firewall: rule removed
```

Block rules apply to incoming WAN traffic only. Blocked packets increment the `drop` counter in `ifstat`. Up to 32 rules.

---

## Port Forwarding

```
> forward tcp 80 192.168.1.100 8080
forward: rule added
```

Forwards incoming WAN TCP/UDP traffic on the specified port to a LAN IP:port. The router rewrites destination IP/port and adjusts checksums (TCP incremental, UDP zeroed). Up to 16 rules.

---

## DNS

```
> dns 8.8.8.8
DNS upstream set to 8.8.8.8
```

The router relays DNS queries (UDP port 53) from LAN clients to the configured upstream DNS server (default: 10.0.2.1). Responses are relayed back to the original client. Up to 32 concurrent DNS queries tracked.

---

## arp / nat / leases / rules

```
> arp
WAN ARP:
  10.0.2.1 -> e6:11:e1:e5:b6:b9
LAN ARP:
  192.168.1.100 -> 3a:26:f0:f3:db:fc
--- 2 entries ---

> nat
icmp 192.168.1.100:1234 -> :10000
--- 1 NAT entries ---

> leases
3a:26:f0:f3:db:fc -> 192.168.1.100
--- 1 leases ---

> rules
Firewall rules:
  BLOCK 10.0.2.99
Port forwards:
  tcp :80 -> 192.168.1.100:8080
--- 2 rules ---
```

---

## Line Editing

- **Backspace** (127/8): delete character
- **Enter** (CR/LF): execute command
- Printable ASCII (32-126): echo and append
- Max line length: 128 characters
