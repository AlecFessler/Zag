# RouterOS Console Reference

The RouterOS console provides an interactive command-line interface over the serial port. It connects to the router process for network operations and displays results on the terminal.

---

## Connecting

The console is available on the QEMU serial port. When using `-serial mon:stdio`, it appears directly in the terminal. With `-serial chardev:pipe`, commands can be piped in programmatically.

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
| `status` | Query the router for its current status |
| `ping <ip>` | Send 4 ICMP echo requests to the given IP address |
| `arp` | Display the router's ARP table |
| `clear` | Clear the terminal screen |

---

## ping

Sends 4 ICMP echo request packets to the specified IPv4 address and displays per-packet results with round-trip time.

```
> ping 10.0.2.1
reply from 10.0.2.1: seq=0 time=291us
reply from 10.0.2.1: seq=1 time=1070us
reply from 10.0.2.1: seq=2 time=1020us
reply from 10.0.2.1: seq=3 time=1027us
--- ping 10.0.2.1: 4 sent, 4 received ---
```

**Behavior:**

- If the target MAC is not in the ARP table, the router sends an ARP request first and waits up to 3 seconds for a reply before each packet.
- Each ICMP echo request has a 3-second timeout. If no reply arrives, the console displays `request timeout: seq=N`.
- If ARP resolution fails, the console displays `ping: ARP timeout for X.X.X.X`.
- Only one ping can be in progress at a time. A second `ping` command while one is active returns `ping: already in progress`.
- Round-trip time is measured in microseconds using the kernel `clock_gettime` syscall.

---

## arp

Displays all entries in the router's ARP table. Entries are learned from incoming ARP packets (both requests and replies).

```
> arp
arp table (2 entries):
10.0.2.1 -> e6:11:e1:e5:b6:b9
10.0.2.2 -> 52:55:0a:00:02:02
```

If the table is empty:

```
> arp
arp table: empty
```

The ARP table holds up to 16 entries. Entries do not expire. When the table is full, the oldest entry (slot 0) is overwritten.

---

## status

Queries the router process and displays its current state.

```
> status
router: running, IP 10.0.2.15, MAC 52:54:00:12:34:56
```

---

## Line Editing

- **Backspace** (ASCII 127 or 8): Delete last character
- **Enter** (CR or LF): Execute command
- Printable characters (ASCII 32–126) are echoed and appended to the line buffer
- Maximum command length: 128 characters
