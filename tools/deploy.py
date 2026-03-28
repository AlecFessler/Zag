#!/usr/bin/env python3
"""Deploy test agents and configure ethernet on all Raspberry Pis.

Requires: pip install fabric

Usage:
  python3 deploy.py              # deploy pi_agent (default)
  python3 deploy.py --agent      # deploy pi_agent (explicit)
  python3 deploy.py --udp-sender # deploy legacy udp_sender
"""

import argparse
import getpass
import os

from fabric import Connection, Config

USERNAME = "alecfessler"

PIES = [
    {"wifi_ip": "192.168.86.79", "eth_ip": "192.168.1.101"},
    {"wifi_ip": "192.168.86.78", "eth_ip": "192.168.1.102"},
    {"wifi_ip": "192.168.86.104", "eth_ip": "192.168.1.103"},
]

GATEWAY = "192.168.1.1"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SENDER_DIR = os.path.join(SCRIPT_DIR, "udp_sender")
AGENT_DIR = os.path.join(SCRIPT_DIR, "pi_agent")


def detect_eth_iface(conn):
    """Detect the wired ethernet interface name (eth0 on older, end0 on Bookworm)."""
    result = conn.run("ip -o link show | grep -v lo | grep -v wlan | awk -F': ' '{print $2}' | head -1", hide=True)
    iface = result.stdout.strip()
    if not iface:
        raise RuntimeError("Could not detect ethernet interface")
    print(f"  Detected ethernet interface: {iface}")
    return iface


def configure_static_ip(conn, eth_iface, eth_ip):
    """Configure a static IP on the ethernet interface."""
    # Check if dhcpcd is managing networking (traditional Raspberry Pi OS)
    result = conn.run("systemctl is-active dhcpcd", hide=True, warn=True)
    uses_dhcpcd = result.ok and "active" in result.stdout.strip()

    if uses_dhcpcd:
        print(f"  Configuring static IP via dhcpcd: {eth_ip}/24")
        static_block = (
            f"\ninterface {eth_iface}\n"
            f"static ip_address={eth_ip}/24\n"
            f"static routers={GATEWAY}\n"
        )
        # Remove any existing static config for this interface, then append
        conn.sudo(f"sed -i '/^interface {eth_iface}/,/^$/d' /etc/dhcpcd.conf")
        conn.run(f"echo '{static_block}' | sudo tee -a /etc/dhcpcd.conf > /dev/null")
        conn.sudo("systemctl restart dhcpcd")
    else:
        # NetworkManager (Bookworm default)
        print(f"  Configuring static IP via NetworkManager: {eth_ip}/24")
        conn_name = f"static-{eth_iface}"
        conn.sudo(f"nmcli connection delete '{conn_name}' 2>/dev/null || true")
        conn.sudo(
            f"nmcli connection add type ethernet ifname {eth_iface} con-name '{conn_name}' "
            f"ipv4.addresses {eth_ip}/24 ipv4.gateway {GATEWAY} ipv4.method manual"
        )
        conn.sudo(f"nmcli connection up '{conn_name}'")


def configure_dhcp(conn, eth_iface):
    """Switch ethernet interface from static IP to DHCP."""
    result = conn.run("systemctl is-active dhcpcd", hide=True, warn=True)
    uses_dhcpcd = result.ok and "active" in result.stdout.strip()

    if uses_dhcpcd:
        print(f"  Switching {eth_iface} to DHCP via dhcpcd")
        conn.sudo(f"sed -i '/^interface {eth_iface}/,/^$/d' /etc/dhcpcd.conf")
        conn.sudo("systemctl restart dhcpcd")
    else:
        print(f"  Switching {eth_iface} to DHCP via NetworkManager")
        conn.sudo(f"nmcli connection delete 'static-{eth_iface}' 2>/dev/null || true")
        conn.sudo(
            f"nmcli connection add type ethernet ifname {eth_iface} con-name '{eth_iface}' "
            f"ipv4.method auto"
        )
        conn.sudo(f"nmcli connection up '{eth_iface}'")


def deploy_sender(conn):
    """Upload and install the UDP sender service."""
    remote_dir = "/opt/udp_sender"
    service_name = "udp_sender.service"
    conn.sudo(f"mkdir -p {remote_dir}")

    local_script = os.path.join(SENDER_DIR, "udp_sender.py")
    local_service = os.path.join(SENDER_DIR, "udp_sender.service")

    # Upload to tmp first, then move with sudo
    conn.put(local_script, "/tmp/udp_sender.py")
    conn.put(local_service, "/tmp/udp_sender.service")

    conn.sudo(f"mv /tmp/udp_sender.py {remote_dir}/udp_sender.py")
    conn.sudo(f"chmod +x {remote_dir}/udp_sender.py")
    conn.sudo(f"mv /tmp/udp_sender.service /etc/systemd/system/{service_name}")

    conn.sudo("systemctl daemon-reload")
    conn.sudo(f"systemctl enable {service_name}")
    conn.sudo(f"systemctl restart {service_name}")


def deploy_agent(conn):
    """Upload and install the Pi test agent service."""
    remote_dir = "/opt/pi_agent"
    service_name = "pi_agent.service"

    # Stop udp_sender if running (replaced by pi_agent)
    conn.sudo("systemctl stop udp_sender.service 2>/dev/null || true")
    conn.sudo("systemctl disable udp_sender.service 2>/dev/null || true")

    conn.sudo(f"mkdir -p {remote_dir}")

    local_script = os.path.join(AGENT_DIR, "pi_agent.py")
    local_service = os.path.join(AGENT_DIR, "pi_agent.service")

    conn.put(local_script, "/tmp/pi_agent.py")
    conn.put(local_service, "/tmp/pi_agent.service")

    conn.sudo(f"mv /tmp/pi_agent.py {remote_dir}/pi_agent.py")
    conn.sudo(f"chmod +x {remote_dir}/pi_agent.py")
    conn.sudo(f"mv /tmp/pi_agent.service /etc/systemd/system/{service_name}")

    conn.sudo("systemctl daemon-reload")
    conn.sudo(f"systemctl enable {service_name}")
    conn.sudo(f"systemctl restart {service_name}")


def main():
    parser = argparse.ArgumentParser(description="Deploy test services to Raspberry Pis")
    parser.add_argument("--agent", action="store_true", default=True,
                        help="Deploy pi_agent test agent (default)")
    parser.add_argument("--udp-sender", action="store_true",
                        help="Deploy legacy UDP sender instead")
    args = parser.parse_args()

    use_agent = not args.udp_sender

    pswd = getpass.getpass("Enter the sudo password for the Pis: ")
    ssh_config = Config(overrides={"sudo": {"password": pswd}})

    mode = "pi_agent" if use_agent else "udp_sender"
    print(f"Deploying: {mode}")

    for pi in PIES:
        host = pi["wifi_ip"]
        eth_ip = pi["eth_ip"]
        print(f"\n=== Deploying to {host} (eth: {eth_ip}) ===")

        conn = Connection(
            host=host,
            user=USERNAME,
            config=ssh_config,
            connect_kwargs={"key_filename": "/home/alec/.ssh/id_ed25519"},
        )

        # Verify python3 exists
        result = conn.run("python3 --version", hide=True, warn=True)
        if not result.ok:
            print(f"  ERROR: python3 not found on {host}, skipping")
            continue
        print(f"  Python: {result.stdout.strip()}")

        eth_iface = detect_eth_iface(conn)
        configure_dhcp(conn, eth_iface)

        if use_agent:
            deploy_agent(conn)
            print(f"  Done! Pi agent running on port 8080, eth set to DHCP")
        else:
            deploy_sender(conn)
            print(f"  Done! UDP sender running, eth set to DHCP")

    print(f"\n=== Deployment complete ({mode}) ===")
    if use_agent:
        print("Pi agents listening on port 8080 (WiFi interface)")
        print("Pis will get IPs via DHCP from the router")
    else:
        print("Pis will send UDP packets to 10.0.2.1:9999 every 3 seconds")


if __name__ == "__main__":
    main()
