import socket
import psutil

def get_active_interface_info():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80)) 
            local_ip = s.getsockname()[0]
    except Exception as e:
        print(f"Error determining local IP: {e}")
        return None

    interfaces = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for iface_name, iface_addrs in interfaces.items():
        for addr in iface_addrs:
            if addr.family == socket.AF_INET and addr.address == local_ip:
                iface_stats = stats.get(iface_name, None)
                return {
                    "interface": iface_name,
                    "ip_address": addr.address,
                    "netmask": addr.netmask,
                    "broadcast": addr.broadcast,
                    "mac_address": next((a.address for a in iface_addrs if a.family == psutil.AF_LINK), None),
                    "is_up": iface_stats.isup if iface_stats else None,
                    "speed_mbps": iface_stats.speed if iface_stats else None,
                    "duplex": (
                        "full" if iface_stats.duplex == psutil.NIC_DUPLEX_FULL else
                        "half" if iface_stats.duplex == psutil.NIC_DUPLEX_HALF else
                        "unknown"
                    ) if iface_stats else None,
                    "mtu": iface_stats.mtu if iface_stats else None
                }

    return None

if __name__ == "__main__":
    info = get_active_interface_info()
    if info:
        print("Active Network Interface Details:")
        for k, v in info.items():
            print(f"{k:>15}: {v}")
    else:
        print("Could not determine active network interface details.")
    