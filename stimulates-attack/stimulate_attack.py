from scapy.all import IP, TCP, UDP, send
import time

target = "127.0.0.1"

for i in range(5):
    pkt = IP(dst=target)/TCP(dport=80, flags="PA")/"GET / HTTP/1.1\r\n\r\n"
    send(pkt, verbose=0)
    time.sleep(0.2)

for i in range(10):
    pkt = IP(dst=target)/TCP(sport=40000+i, dport=80, flags="S")
    send(pkt, verbose=0)
    time.sleep(0.05)

print("Sent test traffic to", target)
