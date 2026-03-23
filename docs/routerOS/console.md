# RouterOS Console Reference

The RouterOS console provides an interactive command-line interface over the serial port. It connects to the router process for network operations and displays results on the terminal.

---

## Connecting

The console is available on the QEMU serial port. When using `-serial mon:stdio`, it appears directly in the terminal. With `-chardev pipe,id=serial0,path=/tmp/pipe`, commands can be piped in programmatically.

On boot, the console displays:

```
=== Zag RouterOS Console ===
Type 'help' for available commands.

>
```

---

## Commands

| Command | Description |
|---------|-------------|
| `help` | List available commands |
| `version` | Display system version string |
| `uptime` | Display time since boot in hours, minutes, seconds |
| `status` | Query router for interface status (IP and MAC per interface) |
| `ping <ip>` | Send 4 ICMP echo requests to the given IP address |
| `arp` | Display ARP tables for all interfaces |
| `nat` | Display the NAT connection tracking table |
| `leases` | Display DHCP lease table |
| `clear` | Clear the terminal screen |

---

## ping

Sends 4 ICMP echo request packets to the specified IPv4 address and displays per-packet results with round-trip time. The router automatically selects the correct interface based on the destination subnet.

```
> ping 10.0.2.1
reply from 10.0.2.1: seq=0 time=291us
reply from 10.0.2.1: seq=1 time=1070us
reply from 10.0.2.1: seq=2 time=1020us
reply from 10.0.2.1: seq=3 time=1027us
--- ping 10.0.2.1: 4 sent, 4 received ---
```

**Behavior:**

- Destinations in the LAN subnet (192.168.1.0/24) are pinged via the LAN interface; all others via WAN.
- If the target MAC is not in the ARP table, the router sends an ARP request first and waits up to 3 seconds.
- Each ICMP echo request has a 3-second timeout.
- Only one ping can run at a time.
- Round-trip time is measured in microseconds.

---

## arp

Displays ARP tables for both WAN and LAN interfaces.

```
> arp
WAN ARP:
  10.0.2.1 -> e6:11:e1:e5:b6:b9
LAN ARP:
  192.168.1.100 -> 3a:26:f0:f3:db:fc
--- 2 entries ---
```

Each interface maintains up to 16 entries. Entries are learned from incoming ARP packets (both requests and replies). No expiration.

---

## nat

Displays the NAT connection tracking table. Entries are created when LAN clients send traffic to WAN destinations.

```
> nat
icmp 192.168.1.100:1234 -> :10000
tcp 192.168.1.100:49152 -> :10001
--- 2 NAT entries ---
```

Each entry shows: protocol, LAN source IP:port, translated WAN port. The table holds up to 128 entries with a 2-minute timeout. Entries are evicted LRU when full.

---

## leases

Displays DHCP leases assigned by the router's LAN-side DHCP server.

```
> leases
3a:26:f0:f3:db:fc -> 192.168.1.100
--- 1 leases ---
```

The DHCP server assigns addresses from the 192.168.1.100-192.168.1.231 range. Up to 32 leases.

---

## status

Displays the router's interface configuration.

```
> status
WAN: 10.0.2.15 (52:54:00:12:34:56)
LAN: 192.168.1.1 (52:54:00:12:34:57)
```

---

## Line Editing

- **Backspace** (ASCII 127 or 8): Delete last character
- **Enter** (CR or LF): Execute command
- Printable characters (ASCII 32–126) are echoed and appended to the line buffer
- Maximum command length: 128 characters
