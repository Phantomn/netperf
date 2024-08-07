import re
import os
import json
from util import Logger

class Parser:
    def __init__(self, log, path):
        self.log = log
        self.info = {}
        self.path = path
        self.logger = Logger.getLogger()

    def extract_info(self):
        from_ip_match = re.search(r'From (\d+\.\d+\.\d+\.\d+:\d+)', self.log)
        to_ip_match = re.search(r'To\s+(\d+\.\d+\.\d+\.\d+:\d+)', self.log)
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

        self.info['is_throughput'] = "충족" if throughput_bps <= threshold_bps else "충족하지 않음"
        self.info['is_latency'] = "충족" if (self.info['average_delay'] * 1000) <= (cycle_period * (1 + tol_period_error)) else "충족하지 않음"
        packet_loss_rate = self.info['packets_dropped'] / self.info['total_packets']
        self.info['is_frame_loss'] = "충족" if packet_loss_rate <= tol_packet_loss else "충족하지 않음"

        self.info['throughput_kbps'] = throughput_bps / 1000
        self.info['threshold_kbps'] = threshold_bps / 1000

        output = os.path.join(self.path, "results.json")
        with open(output, 'w') as file:
            json.dump(self.info, file, indent=4)

        self.logger.info(f"Analyze Results: {output}")
        self.logger.info(f"Throughput(kbps): {self.info['throughput_kbps']:.02f}, 결과: {self.info['is_throughput']}")
        self.logger.info(f"Latency: {(self.info['average_delay'] * 1000):.02f}, 결과: {self.info['is_latency']}")
        self.logger.info(f"Frame Loss: {packet_loss_rate:.02f}, 결과: {self.info['is_frame_loss']}")
        if self.info['is_throughput'] or self.info['is_latency'] or self.info['is_frame_loss'] in "충족하지 않음":
            self.logger.info("최종 결과: 실패")
