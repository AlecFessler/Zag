"""Sniff first TCP SYN-ACK on tap0 and tap1, print hex dumps."""
import socket
import struct
import threading

def sniff_iface(iface, results, label):
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    raw.bind((iface, 0))
    raw.settimeout(10)
    while True:
        try:
            data = raw.recv(2048)
            if len(data) < 48: continue
            ethertype = struct.unpack("!H", data[12:14])[0]
            if ethertype != 0x0800: continue
            if data[23] != 6: continue  # TCP only
            flags = data[47]
            if flags & 0x12 == 0x12:  # SYN+ACK
                results.append((label, data))
                break
        except socket.timeout:
            break
    raw.close()

r0, r1 = [], []
t0 = threading.Thread(target=sniff_iface, args=("tap0", r0, "tap0"))
t1 = threading.Thread(target=sniff_iface, args=("tap1", r1, "tap1"))
t0.start()
t1.start()
t0.join(timeout=12)
t1.join(timeout=12)

for label, data in r0 + r1:
    src_ip = ".".join(str(b) for b in data[26:30])
    dst_ip = ".".join(str(b) for b in data[30:34])
    sport = struct.unpack("!H", data[34:36])[0]
    dport = struct.unpack("!H", data[36:38])[0]
    seq = struct.unpack("!I", data[38:42])[0]
    ack = struct.unpack("!I", data[42:46])[0]
    print(f"\n{label} SYN-ACK: {src_ip}:{sport} -> {dst_ip}:{dport} seq={seq} ack={ack}")
    # Print TCP header bytes (offset 34 to 54)
    tcp_hdr = data[34:min(len(data), 74)]
    print(f"  TCP header hex: {tcp_hdr.hex()}")
    # Print full IP+TCP
    print(f"  Frame len={len(data)}, IP total={struct.unpack('!H', data[16:18])[0]}")
    print(f"  dst_mac={':'.join(f'{b:02x}' for b in data[0:6])}")

if not r0: print("\nNo SYN-ACK captured on tap0")
if not r1: print("\nNo SYN-ACK captured on tap1")
