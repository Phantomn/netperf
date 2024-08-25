from tqdm import tqdm
from scapy.all import Ether, IP, TCP, sr1, send, sendp, conf
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from util import Logger

class Suite:
    def __init__(self, iface, src_mac, src_ip, dst_mac, dst_ip, test_type, duration=5, rate_limit=14880):
        self.iface = iface
        self.src_mac = src_mac
        self.src_ip = src_ip
        self.dst_mac = dst_mac
        self.dst_ip = dst_ip
        self.duration = duration
        self.rate_limit = rate_limit
        self.test_type = test_type
        self.open_ports = []
        self.open_ports_lock = threading.Lock()
        self.logger = Logger.getLogger()
        self.chunk_size = 10

        conf.iface = self.iface
        conf.verb = 0
        conf.sniff_promisc = True
        conf.checkIPaddr = False

    def scan_port(self, port):
        try:
            pkt = IP(dst=self.dst_ip) / TCP(dport=port, flags='S')
            response = sr1(pkt, timeout=0.5, verbose=0)
            if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                with self.open_ports_lock:
                    self.open_ports.extend(port)
            send(IP(dst=self.dst_ip) / TCP(dport=port, flags='R'), verbose=0)
        except Exception as e:
            self.logger.error(f"Error scanning port {port}: {e}")

    def discover_open_ports(self, start_port, end_port):
        with ThreadPoolExecutor() as executor:
            futures = []
            for chunk_start in range(start_port, end_port, self.chunk_size):
                chunk_end = min(chunk_start + self.chunk_size, end_port)
                port_range = range(chunk_start, chunk_end)
                futures.append(executor.submit(self.scan_port, port_range))

            with tqdm(total=end_port - start_port, unit=" port", desc="Scanning Ports", ncols=100) as progress_bar:
                for future in as_completed(futures):
                    future.result()
                    progress_bar.update(self.chunk_size)

    def gen_packet(self, protocol="tcp", port=None, packet_length=60):
        eth_frame = Ether(src=self.src_mac, dst=self.dst_mac)
        ip_frame = IP(src=self.src_ip, dst=self.dst_ip)

        if protocol == "tcp":
            tcp_frame = TCP(sport=random.randint(1024, 65535), dport=port or random.randint(1, 65535), flags="S")
            return eth_frame / ip_frame / tcp_frame
        elif protocol == "udp":
            udp_frame = UDP(sport=random.randint(1024, 65535), dport=port or random.randint(1, 65535))
            return eth_frame / ip_frame / udp_frame / Raw(load=RandString(size=packet_length-(len(eth_frame)+len(ip_frame)+len(udp_frame))))
        elif protocol == "icmp":
            icmp_frame = ICMP()
            return eth_frame / ip_frame / icmp_frame
        elif protocol == "arp":
            arp_frame = ARP(pdst=self.dst_ip)
            return eth_frame / arp_frame
        else:
            raise ValueError(f"Unsupported protocol: {protocol}")

    def perform_test(self):
        start_time = time.time()
        count = 0

        with tqdm(total=self.duration, unit=" s", desc=f"Performing {self.test_type.capitalize()} Test", ncols=100, leave=False) as progress_bar:
            while time.time() - start_time < self.duration:
                elapsed_time = int(time.time() - start_time)
                progress_bar.update(elapsed_time - progress_bar.n)

                if self.test_type == "scan":
                    for port in self.open_ports:
                        packet = self.generate_packet(protocol="tcp", port=port)
                        sendp(packet, iface=self.iface, verbose=0)
                        count += 1
                elif self.test_type == "storm":
                    packet = self.generate_packet(protocol="tcp")  # TCP 패킷을 무작위로 생성
                    sendp(packet, iface=self.iface, verbose=0)
                    count += 1

                if count >= self.rate_limit:
                    elapsed_time = time.time() - start_time
                    remaining_time = max(0, 1 - elapsed_time % 1)
                    time.sleep(remaining_time)
                    count = 0

    def run(self):
        if self.test_type == "scan":
            self.logger.info("Discovering open ports...")
            self.discover_open_ports(7000, 9000)
            if not self.open_ports:
                self.logger.info("No open ports discovered. Exiting.")
                return False
            self.logger.info(f"Open ports discovered: {self.open_ports}")

        self.logger.info(f"Performing {self.test_type.capitalize()} Test...")
        if not self.perform_test():
            self.logger.error("Failed to perform test")
            return False

        return True
