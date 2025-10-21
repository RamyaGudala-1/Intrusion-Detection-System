from scapy.all import (
    get_if_list,
    get_if_addr,
    get_if_hwaddr,
    conf
)
import socket

def get_active_interface_scapy():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception as e:
        print(f"Error getting local IP: {e}")
        return None

    print("Network Interface List:")
    for iface in get_if_list():
        print(iface)
        try:
            iface_ip = get_if_addr(iface)
            if iface_ip == local_ip:
                iface_mac = get_if_hwaddr(iface)
                return {
                    "interface": iface,
                    "ip_address": iface_ip,
                    "mac_address": iface_mac
                }
        except Exception:
            continue

    return None

if __name__ == "__main__":
    iface_info = get_active_interface_scapy()
    if iface_info:
        print("Active Network Interface Info (by Scapy):")
        for k, v in iface_info.items():
            print(f"{k:>12}: {v}")
    else:
        print("Could not detect active interface by Scapy.")
