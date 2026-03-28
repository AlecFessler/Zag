#!/usr/bin/env python3
"""Send UDP packets to the default gateway every 3 seconds for router testing."""

import socket
import time

TARGET = "10.0.2.1"  # mock ISP gateway (Realtek) — forces router to NAT+forward
PORT = 9999
INTERVAL = 3.0

def main():
    hostname = socket.gethostname()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 0
    while True:
        msg = f"{hostname} seq={seq}".encode()
        sock.sendto(msg, (TARGET, PORT))
        seq += 1
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
