import re
import os
import json
import time
from netperf.net_info import get_path

class Parser:
    def __init__(self, log):
        self.log = log
        self.info = {}
        self.timestamp = time.strftime("%Y%m%d")

    def extract_info(self):
        from_ip_match = re.search(r'From (\d+\.\d+\.\d+\.\d+):\d+', self.log)
        to_ip_match = re.search(r'To\s+(\d+\.\d+\.\d+\.\d+):\d+', self.log)
        if from_ip_match and to_ip_match:
            self.info['from_ip'] = from_ip_match.group(1)
            self.info['to_ip'] = to_ip_match.group(1)

        # "----------------------------------------------------------" 이후의 데이터 추출
        data_sections = re.split(r'-{58}', self.log)
        
        if len(data_sections) >= 3:
            results_data = data_sections[2].strip().split('\n')
            for line in results_data:
                if '=' in line:
                    key_value = re.split(r'\s+=\s+', line)
                    if len(key_value) == 2:
                        key = key_value[0].strip().lower().replace(' ', '_')
                        value = key_value[1].split(' ')[0]
                        try:
                            value = float(value)
                        except ValueError:
                            pass
                        self.info[key] = value

        # 분석 및 출력
        bits_received = self.info['bytes_received'] * 8
        throughput_bps = bits_received / self.info['total_time']
        threshold_bps = 100 * 1000000 * 0.1  # 10% of 100 Mbps

        cycle_period = 1000
        tol_period_error = 0.04
        tol_packet_loss = 0.1

        is_throughput = throughput_bps <= threshold_bps
        is_discrete_monitor = (self.info['average_delay'] * 1000) <= (cycle_period * (1 + tol_period_error))
        packet_loss_rate = self.info['packets_dropped'] / self.info['total_packets']
        is_icmp_monitor = packet_loss_rate <= tol_packet_loss

        self.print_analysis(throughput_bps, threshold_bps, is_throughput, is_discrete_monitor, is_icmp_monitor)
        
        output = os.path.join(get_path(None), "results", self.timestamp, f"{self.log}.json")
        with open(output, 'w') as file:
            json.dump(self.info, file, indent=4)
            
        print(f"Analyze Results : {output}")
        
    def print_analysis(self, throughput_bps, threshold_bps, is_throughput, is_discrete_monitor, is_icmp_monitor):
        throughput_kbps = throughput_bps / 1000
        threshold_kbps = threshold_bps / 1000
        print(f"Throughput: {throughput_kbps:.2f} Kbps")
        print(f"기준 Throughput: {threshold_kbps:.2f} Kbps")
        print(f"Throughput 기준 충족 여부: {'충족' if is_throughput else '충족하지 않음'}")
        print(f"Discrete Monitor 기준 충족 여부: {'충족' if is_discrete_monitor else '충족하지 않음'}")
        print(f"ICMP Monitor 기준 충족 여부: {'충족' if is_icmp_monitor else '충족하지 않음'}")