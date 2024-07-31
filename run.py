import paramiko
import subprocess
import os
import time
import logging
import argparse

# 설정 값
SENDER_DIR = os.path.expanduser("~/netperf")

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

def ssh_connect(ip, ssh_user, ssh_pass):
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(ip, username=ssh_user, password=ssh_pass)
    return ssh_client

def ssh_command(client, command, get_output=False):
    stdin, stdout, stderr = client.exec_command(command)
    stdout.channel.recv_exit_status()  # 블로킹 호출로 명령 실행 완료 대기
    if get_output:
        return stdout.read().decode().strip(), stderr.read().decode().strip()
    return None, None

def get_path(client):
    receiver_path, _ = ssh_command(client, "find /home -type d -name 'netperf'", get_output=True)
    return receiver_path

def get_nic_info(client, remote_flag=False):
    if remote_flag:
        nic, _ = ssh_command(client, "ip -o -4 route show to default | awk '{print $5}'", get_output=True)
        mac, _ = ssh_command(client, f"cat /sys/class/net/{nic}/address", get_output=True)
    else:
        nic = subprocess.getoutput("ip -o -4 route show to default | awk '{print $5}'")
        mac = subprocess.getoutput(f"cat /sys/class/net/{nic}/address")
    return nic, mac

def run_tcpdump(client, interface, receiver_dir, tcpdump_file, ssh_pass):
    tcpdump_command = f"sudo -S nohup tcpdump -i {interface} -w {receiver_dir}/logs/{tcpdump_file} > /dev/null 2>&1 & echo $!"
    stdin, stdout, stderr = client.exec_command(f"echo {ssh_pass} | {tcpdump_command}")
    tcpdump_pid = stdout.read().decode().strip()
    return tcpdump_pid

def start_itgrecv(client, receiver_dir):
    itgrecv_command = f"nohup {receiver_dir}/bin/ITGRecv > {receiver_dir}/logs/itgrecv.log 2>&1 & echo $!"
    stdin, stdout, stderr = client.exec_command(itgrecv_command)
    itg_recv_pid = stdout.read().decode().strip()
    time.sleep(2)  # ITGRecv가 시작될 시간을 줍니다.
    return itg_recv_pid

def start_scapy(scapy_script_name):
    try:
        process = subprocess.Popen(["sudo", "python3", os.path.join(SENDER_DIR, "codes", scapy_script_name)])
        time.sleep(2)  # Scapy가 시작될 시간을 줍니다.
        return process.pid
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to start Scapy Syn Storm: {e}")
        raise

def start_itgsend(receiver_ip, log_dir, receiver_dir):
    itg_send_command = [
        os.path.join(SENDER_DIR, "bin", "ITGSend"),
        "-T", "TCP",
        "-a", receiver_ip,
        "-C", "14880",
        "-t", "120000",
        "-l", os.path.join(log_dir, "sender.log"),
        "-x", os.path.join(receiver_dir, "logs", "receiver.log")
    ]
    try:
        result = subprocess.run(itg_send_command, check=True)
        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, itg_send_command)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to start ITGSend: {e}")
        raise

def download_files(sftp_client, remote_path, local_path):
    sftp_client.get(remote_path, local_path)

def kill_remote_process(client, pid, ssh_pass):
    kill_command = f"sudo -S kill {pid}"
    ssh_command(client, f"echo {ssh_pass} | {kill_command}")

def cleanup_processes(client, processes, ssh_pass):
    for pid in processes:
        if pid:
            kill_remote_process(client, pid, ssh_pass)

def main(receiver_ip, sender_ssh_pw, receiver_ssh_id, receiver_ssh_pw, scapy_script_name):
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    log_dir = os.path.join(SENDER_DIR, "logs", timestamp)
    os.makedirs(log_dir, exist_ok=True)
    TCPDUMP_FILE = f"{scapy_script_name}.pcap"

    # Sender의 NIC 및 MAC 정보 확인
    logger.info("Getting NIC and MAC information for Sender...")
    sender_nic, sender_mac = get_nic_info(None)
    logger.info(f"Sender NIC: {sender_nic}, MAC: {sender_mac}")
    
    # Receiver의 네트워크 인터페이스 확인 및 netperf 경로 검색
    receiver_client = ssh_connect(receiver_ip, receiver_ssh_id, receiver_ssh_pw)
    receiver_nic, receiver_mac = get_nic_info(receiver_client, True)
    logger.info(f"Receiver NIC: {receiver_nic}, MAC: {receiver_mac}")

    receiver_path = get_path(receiver_client)
    logger.info(f"Receiver netperf path: {receiver_path}")

    try:
        # tcpdump 시작
        logger.info("Starting tcpdump on receiver...")
        tcpdump_pid = run_tcpdump(receiver_client, receiver_nic, receiver_path, TCPDUMP_FILE, receiver_ssh_pw)
        logger.info(f"tcpdump started with PID {tcpdump_pid}")

        # ITGRecv 시작
        logger.info("Starting ITGRecv on receiver...")
        itg_recv_pid = start_itgrecv(receiver_client, receiver_path)
        logger.info(f"ITGRecv started with PID {itg_recv_pid}")

        # Scapy Syn Storm 시작
        logger.info("Starting Scapy Syn Storm...")
        scapy_pid = start_scapy(scapy_script_name)
        logger.info(f"Scapy Syn Storm started with PID {scapy_pid}")

        # ITGSend 시작
        logger.info("Starting ITGSend for performance measurement...")
        start_itgsend(receiver_ip, log_dir, receiver_path)
        logger.info("ITGSend completed successfully.")

        # Receiver log 파일 다운로드
        logger.info("Downloading receiver log file...")
        sftp_client = receiver_client.open_sftp()
        download_files(sftp_client, os.path.join(receiver_path, "logs", "receiver.log"), os.path.join(log_dir, "receiver.log"))

        # tcpdump 캡처 파일 다운로드
        logger.info("Downloading tcpdump capture file...")
        ssh_command(receiver_client, f"tar -P -zcvf {os.path.join(receiver_path, 'logs', TCPDUMP_FILE)}.tar.gz {os.path.join(receiver_path, 'logs', TCPDUMP_FILE)}")
        download_files(sftp_client, f"{os.path.join(receiver_path, 'logs', TCPDUMP_FILE)}.tar.gz", os.path.join(log_dir, f"{TCPDUMP_FILE}.tar.gz"))
        logger.info("tcpdump capture file downloaded successfully.")

    finally:
        logger.info("Cleaning up processes...")
        cleanup_processes(receiver_client, [tcpdump_pid, itg_recv_pid, scapy_pid], receiver_ssh_pw)
        receiver_client.close()

    logger.info("Successfully Test Finish")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network performance test script.")
    parser.add_argument("receiver_ip", help="IP address of the receiver.")
    parser.add_argument("sender_ssh_pw", help="SSH password for the sender.")
    parser.add_argument("receiver_ssh_id", help="SSH username for the receiver.")
    parser.add_argument("receiver_ssh_pw", help="SSH password for the receiver.")
    parser.add_argument("scapy_script_name", help="Name of the Scapy script to run.")

    args = parser.parse_args()
    main(args.receiver_ip, args.sender_ssh_pw, args.receiver_ssh_id, args.receiver_ssh_pw, args.scapy_script_name)
