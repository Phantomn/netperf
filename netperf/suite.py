from tqdm import tqdm
from scapy.all import Ether, IP, TCP, sr1, send, sendp, conf
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from util import Logger


class Suite:
    def __init__(self, iface, src_mac, src_ip, dst_mac, dst_ip, duration=5, rate_limit=14880):
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

    def gen_packet(self, dst_port):
        eth_frame = Ether(src=self.src_mac, dst=self.dst_mac)
        ip_frame = IP(src=self.src_ip, dst=self.dst_ip)
        tcp_frame = TCP(sport=random.randint(
            1024, 65535), dport=dst_port, flags="S")
        packet = eth_frame / ip_frame / tcp_frame
        return packet

    def perform_test(self):
        start_time = time.time()
        count = 0

        with tqdm(total=self.duration, unit=" s", desc="Performing Test", ncols=100, leave=False) as progress_bar:
            while time.time() - start_time < self.duration:
                elapsed_time = int(time.time() - start_time)
                progress_bar.update(elapsed_time - progress_bar.n)

                for port in self.open_ports:
                    for adj_port in (port, port - 1, port + 1):
                        if 1 <= adj_port <= 65535:
                            pkt = self.gen_packet(port)
                            sendp(pkt, iface=self.iface, verbose=0)
                            count += 1

                            if count >= self.rate_limit:
                                elapsed_time = time.time() - start_time
                                remaining_time = max(0, 1 - elapsed_time % 1)
                                time.sleep(remaining_time)
                                count = 0

    def run(self):
        self.logger.info("Discovering open ports...")
        self.discover_open_ports(7000, 9000)
        if not self.open_ports:
            self.logger.info("No open ports discovered. Exiting.")
            return False
        self.logger.info(f"Open ports discovered: {self.open_ports}")
        self.logger.info("Performing Test...")
        if self.perform_test():
            self.logger.error("Failed perform Test")
            return False
        return True
