from scapy.all import Ether, IP, TCP, sr1, send, sendp, conf
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from log_utils import Logger

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
        self.logger = Logger.getLogger()
        random.seed()
        
        conf.iface = self.iface
        conf.verb = 0
        conf.sniff_promisc = True
        conf.checkIPaddr = False

    def scan_port(self, port):
        try:
            pkt = IP(dst=self.dst_ip) / TCP(dport=port, flags='S')
            response = sr1(pkt, timeout=0.5)
            if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                with self.open_ports_lock:
                    self.open_ports.append(port)
                    self.logger.info(f"Scan port: {port}")
                send(IP(dst=self.dst_ip) / TCP(dport=port, flags='R'))
        except Exception as e:
            self.logger.error(f"Error scanning port {port}: {e}")

    def discover_open_ports(self):
        port_range = range(1, 65535)
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(self.scan_port, port) for port in port_range}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.logger.error(f"Error in port scanning task: {e}")

    def gen_packet(self, dst_port):
        eth_frame = Ether(src=self.src_mac, dst=self.dst_mac)
        ip_frame = IP(src=self.src_ip, dst=self.dst_ip)
        tcp_frame = TCP(sport=random.randint(1024, 65535), dport=dst_port, flags="S")
        packet = eth_frame / ip_frame / tcp_frame
        return packet

    def perform_test(self):
        start_time = time.time()
        count = 0
        
        while time.time() - start_time < self.duration:
            for port in self.open_ports:
                for adj_port in (port, port - 1, port + 1):
                    if 1 <= adj_port <= 65535:
                        elapsed_time = time.time() - start_time
                        remaining_time = max(0, 1 - elapsed_time % 1)
                        self.logger.info(f"{elapsed_time} {remaining_time}")
                        
                        pkt = self.gen_packet(port)
                        sendp(pkt, iface=self.iface)
                        count += 1
                
                        if count >= self.rate_limit:
                            elapsed_time = time.time() - start_time
                            remaining_time = max(0, 1 - elapsed_time % 1)
                            time.sleep(remaining_time)
                            count = 0
        return True

    def run(self):
        self.logger.info("Discovering open ports...")
        self.discover_open_ports()

        if not self.open_ports:
            self.logger.info("No open ports discovered. Exiting.")
            return False
        else:
            self.logger.info(f"Open ports discovered: {self.open_ports}")
            self.logger.info(f"Performing Test...")
            if not self.perform_test():
                self.logger.error("Failed perform Test")
                return False
            else:
                return True