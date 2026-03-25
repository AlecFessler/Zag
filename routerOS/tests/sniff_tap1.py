"""Sniff TCP packets on tap1 using raw AF_PACKET socket."""
import socket
import struct

raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
raw.bind(("tap1", 0))
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
            dst_mac = ":".join(f"{b:02x}" for b in data[0:6])
            src_mac = ":".join(f"{b:02x}" for b in data[6:12])
            if proto == 6:
                sport = struct.unpack("!H", data[34:36])[0]
                dport = struct.unpack("!H", data[36:38])[0]
                flags = data[47]
                parts = []
                if flags & 0x02: parts.append("SYN")
                if flags & 0x10: parts.append("ACK")
                if flags & 0x01: parts.append("FIN")
                if flags & 0x04: parts.append("RST")
                # Verify TCP checksum
                ip_hdr_len = (data[14] & 0x0F) * 4
                ip_total = struct.unpack("!H", data[16:18])[0]
                tcp_len = ip_total - ip_hdr_len
                tcp_start = 14 + ip_hdr_len
                tcp_end = tcp_start + tcp_len
                # Build pseudo-header
                pseudo = data[26:30] + data[30:34] + b'\x00\x06' + struct.pack("!H", tcp_len)
                # Sum pseudo + TCP segment (with existing checksum)
                payload = pseudo + data[tcp_start:tcp_end]
                if len(payload) % 2: payload += b'\x00'
                s = 0
                for i in range(0, len(payload), 2):
                    s += struct.unpack("!H", payload[i:i+2])[0]
                while s >> 16: s = (s & 0xFFFF) + (s >> 16)
                csum_ok = "OK" if s == 0xFFFF else f"BAD(sum={s:#06x})"
                seq = struct.unpack("!I", data[38:42])[0]
                ack_num = struct.unpack("!I", data[42:46])[0]
                print(f"TCP {src_ip}:{sport}->{dst_ip}:{dport} [{' '.join(parts)}] seq={seq} ack={ack_num} len={len(data)} csum={csum_ok}")
                count += 1
    except socket.timeout:
        break
raw.close()
print(f"Captured {count} TCP packets on tap1")
