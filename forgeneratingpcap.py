from scapy.all import IP, TCP, Ether, wrpcap, RandShort, RandIP
from scapy.data import ETH_P_IP
import os
import random
from datetime import datetime, timedelta

# Parameters
num_packets = 500
base_time = datetime.now()
packets = []

for i in range(num_packets):
    src_ip = str(RandIP())
    dst_ip = str(RandIP())
    src_port = RandShort()
    dst_port = 80
    payload_size = random.randint(100, 1500)

    ether = Ether(type=ETH_P_IP)
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(sport=src_port, dport=dst_port, seq=random.randint(1000, 100000))
    payload = os.urandom(payload_size)

    pkt = ether / ip / tcp / payload
    pkt.time = (base_time + timedelta(seconds=i * 0.01)).timestamp()
    packets.append(pkt)

wrpcap("bandwidth_analysis_simulated.pcap", packets)
print("✅ PCAP file generated: bandwidth_analysis_simulated.pcap")
