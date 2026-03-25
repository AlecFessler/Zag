"""Sniff TCP packets on tap0 using raw AF_PACKET socket."""
import socket
import struct
import time

raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
raw.bind(("tap0", 0))
raw.settimeout(8)
count = 0
while count < 20:
    try:
        data = raw.recv(2048)
        ethertype = struct.unpack("!H", data[12:14])[0]
        if ethertype == 0x0800:
            proto = data[23]
            src_ip = ".".join(str(b) for b in data[26:30])
            dst_ip = ".".join(str(b) for b in data[30:34])
            ip_total = struct.unpack("!H", data[16:18])[0]
            if proto == 6:
                sport = struct.unpack("!H", data[34:36])[0]
                dport = struct.unpack("!H", data[36:38])[0]
                flags = data[47]
                parts = []
                if flags & 0x02:
                    parts.append("SYN")
                if flags & 0x10:
                    parts.append("ACK")
                if flags & 0x01:
                    parts.append("FIN")
                if flags & 0x04:
                    parts.append("RST")
                flag_str = " ".join(parts)
                # Also check TCP checksum
                print(f"TCP {src_ip}:{sport} -> {dst_ip}:{dport} [{flag_str}] framelen={len(data)} ip_total={ip_total}")
                count += 1
    except socket.timeout:
        break
raw.close()
print(f"Captured {count} TCP packets")
