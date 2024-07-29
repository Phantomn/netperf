import json
import re

# 로그 파일에서 필요한 정보를 추출하는 함수
def extract_info(log_content):
    info = {}
    output = {}

    # IP 정보 추출
    from_ip_match = re.search(r'From (\d+\.\d+\.\d+\.\d+):\d+', log_content)
    to_ip_match = re.search(r'To\s+(\d+\.\d+\.\d+\.\d+):\d+', log_content)
    if from_ip_match and to_ip_match:
        info['from_ip'] = from_ip_match.group(1)
        info['to_ip'] = to_ip_match.group(1)

    # "----------------------------------------------------------" 이후의 데이터 추출
    data_sections = re.split(r'-{58}', log_content)
    
    if len(data_sections) >= 3:
        # 두 번째 섹션은 Flow 데이터
        flow_data = data_sections[1].strip().split('\n')
        for line in flow_data:
            if '=' in line:
                key_value = re.split(r'\s+=\s+', line)
                if len(key_value) == 2:
                    key = key_value[0].strip().lower().replace(' ', '_')
                    value = key_value[1].split(' ')[0]
                    # 숫자는 float으로 변환
                    try:
                        value = float(value)
                    except ValueError:
                        pass
                    info[key] = value

        # 세 번째 섹션은 Total Results 데이터
        total_results_data = data_sections[2].strip().split('\n')
        for line in total_results_data:
            if '=' in line:
                key_value = re.split(r'\s+=\s+', line)
                if len(key_value) == 2:
                    key = key_value[0].strip().lower().replace(' ', '_')
                    value = key_value[1].split(' ')[0]
                    # 숫자는 float으로 변환
                    try:
                        value = float(value)
                    except ValueError:
                        pass
                    info[key] = value
        
    bits_received = info['bytes_received'] * 8
    throughput_bps = bits_received / info['total_time']
    throughput_kbps = throughput_bps / 1000

    link_speed_mbps = 100 * 1000000
    link_utilization_threshold = 0.1
    throughput_threshold_bps = link_speed_mbps * link_utilization_threshold

    cycle_period_ms = 1000
    tolerable_period_error = 0.04
    icmp_timeout = 0.5
    tolerable_packet_loss = 0.1

    is_within_throughput_threshold = throughput_bps <= throughput_threshold_bps
    is_within_discrete_monitor_threshold = (info['average_delay'] * 1000) <= (cycle_period_ms * (1 + tolerable_period_error))

    packet_loss_percentage = info['packets_dropped'] / info['total_packets']
    is_within_icmp_monitor_threshold = packet_loss_percentage <= tolerable_packet_loss

    # 결과 출력
    print(f"Throughput: {throughput_kbps:.2f} Kbps")
    print(f"기준 Throughput: {throughput_threshold_bps / 1000:.2f} Kbps")
    print(f"Throughput 기준 충족 여부: {'충족' if is_within_throughput_threshold else '충족하지 않음'}")
    print(f"Discrete Monitor 기준 충족 여부: {'충족' if is_within_discrete_monitor_threshold else '충족하지 않음'}")
    print(f"ICMP Monitor 기준 충족 여부: {'충족' if is_within_icmp_monitor_threshold else '충족하지 않음'}")


# 로그 파일 읽기
with open('./logs/20240729_172028/output.txt', 'r') as log_file:
    log_content = log_file.read()

# 정보 추출
info = extract_info(log_content)

# JSON 파일로 저장
with open('log_info.json', 'w') as json_file:
    json.dump(info, json_file, indent=4)

print("success convert json : log_info.json")
