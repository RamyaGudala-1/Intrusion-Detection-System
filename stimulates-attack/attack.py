from scapy.all import IP, TCP, Ether
import time

try:
    from detect_intrusion import detect as process_packet
except Exception:
    def process_packet(pkt):
        print("process_packet called:", pkt.summary())

src_ip = "10.0.0.5"       
base_dst = "10.0.1."      
sport = 12345
dports = [80]             

num_targets = 100         
interval = 0.02           

packets = []
for i in range(1, num_targets + 1):
    dst_ip = f"{base_dst}{i % 254}"  
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(sport=sport, dport=dports[0], flags="S")
    pkt = Ether() / ip / tcp
    packets.append(pkt)

print(f"Feeding {len(packets)} synthetic packets into IDS handler...")
for pkt in packets:
    try:
        process_packet(pkt)
    except TypeError:
        process_packet(bytes(pkt))
    time.sleep(interval)

print("Done. Check your IDS logs/alerts.")
        