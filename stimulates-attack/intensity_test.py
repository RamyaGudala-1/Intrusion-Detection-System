# intensity_test.py
from scapy.all import IP, TCP, Ether
import time

try:
    from detect_intrusion import detect as process_packet
except Exception:
    def process_packet(pkt):
        print("process_packet called:", pkt.summary())

src_ip = "10.0.0.5"
base_dst = "10.0.1."
sport = 40000

num_targets = 2000       
interval = 0.0005        
ports = [80, 22, 443, 8080, 53] 

count = 0
for i in range(1, num_targets + 1):
    dst_ip = f"{base_dst}{(i % 250) + 1}"
    dport = ports[i % len(ports)]
    pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="S")
    pkt.time = time.time()
    process_packet(pkt)
    count += 1
    if count % 200 == 0:
        print("Sent locally to handler:", count)
    time.sleep(interval)

print("Done intensity test.")
