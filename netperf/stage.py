import os
import time
from ssh_utils import SSHClient
from net_info import get_nic_info, get_path, get_recent_dir, get_nic_ip
from proc_manager import ProcessManager
from suite import Suite
from log_utils import Logger

class Stage:
    def __init__(self, sender_ssh_pw, receiver_ip, receiver_ssh_id, receiver_ssh_pw, test):
        self.sender_ssh_pw = sender_ssh_pw
        self.receiver_ip = receiver_ip
        self.receiver_ssh_id = receiver_ssh_id
        self.receiver_ssh_pw = receiver_ssh_pw
        self.test = test
        self.tcpdump_file = f"{test}.pcap"
        self.sender_dir = get_path(None, None)
        self.timestamp = time.strftime("%Y%m%d")
        os.makedirs(os.path.join(self.sender_dir, "logs"), exist_ok=True)
        log_path = os.path.join(get_recent_dir(self.sender_dir, self.timestamp))
        if not os.path.exists(log_path):
            os.makedirs(log_path)
        Logger.configure(log_path, self.test)
        self.logger = Logger.getLogger()
        
        self.client = None
        self.process_manager = None
        self.sender_nic = None
        self.sender_mac = None
        self.sender_ip = None
        self.receiver_nic = None
        self.receiver_mac = None
        self.receiver_dir = None
        self.tcpdump_pid = None
        self.itgrecv_pid = None
        
    def handle_stage(self, stage_name, func, *args, **kwargs):
        try:
            result = func(*args, **kwargs)
            return result
        except Exception as e:
            self.logger.error(f"Failed to complete {stage_name}: {e}")
            return None
    
    def setup(self):
        self.logger.info(f"Sender SSH PW : {self.sender_ssh_pw}")
        self.logger.info(f"Receiver IP : {self.receiver_ip}")
        self.logger.info(f"Receiver SSH : {self.receiver_ssh_id}/{self.receiver_ssh_pw}")
        self.logger.info(f"Test Type : {self.test}")
        self.sender_nic, self.sender_mac = self.handle_stage(
            "Getting NIC and MAC information for Sender", get_nic_info,
            None)
        if not self.sender_nic:
            return False
        self.sender_ip = get_nic_ip()
        self.client = SSHClient(self.receiver_ip, self.receiver_ssh_id, self.receiver_ssh_pw)
        self.receiver_nic, self.receiver_mac = self.handle_stage(
            "Getting NIC information for Receiver", get_nic_info, 
            self.client, True)
        self.logger.info(f"Sender Network info {self.sender_nic}, {self.sender_ip}, {self.sender_mac}")
        self.logger.info(f"Receiver Network info {self.receiver_nic}, {self.receiver_ip}, {self.receiver_mac}")
        if not self.receiver_nic:
            return False
        
        self.receiver_dir = self.handle_stage("Getting base for Receiver", get_path, self.client, True)
        if not self.receiver_dir:
            return False
        
        self.process_manager = ProcessManager(self.client)
        if not self.process_manager:
            return False
        self.suite = Suite(self.sender_nic, self.sender_mac, self.sender_ip, self.receiver_mac, self.receiver_ip)
        if not self.suite:
            return False
        return True
    
    def run(self):
        if not self.setup():
            return
        self.tcpdump_pid = self.handle_stage(
            "Starting tcpdump on receiver",
            self.process_manager.run_process,
            "tcpdump",
            iface=self.receiver_nic,
            receiver_dir=self.receiver_dir,
            tcpdump_file=self.tcpdump_file,
            ssh_pass=self.receiver_ssh_pw)
        if not self.tcpdump_pid:
            return
        self.itgrecv_pid = self.handle_stage(
            "Starting ITGRecv on receiver",
            self.process_manager.run_process,
            "itgrecv",
            receiver_dir=self.receiver_dir)
        if not self.itgrecv_pid:
            return
        if not self.handle_stage(
            f"Starting {self.test} Test",
            self.suite.run):
            return
        if not self.handle_stage(
            "Starting ITGSend for performance measurement",
            self.process_manager.run_process,
            "itgsend",
            receiver_ip=self.receiver_ip,
            sender_dir=self.sender_dir,
            receiver_dir=self.receiver_dir):
            return
        sftp_client = self.client.ssh_client.open_sftp()
        if not self.handle_stage(
            "Downloading receiver log file",
            self.process_manager.run_process,
            "download",
            sftp_client=sftp_client,
            remote_path = os.path.join(self.receiver_dir, "logs", "receiver.log"),
            local_path = os.path.join(self.sender_dir, "logs", "receiver.log")):
            return
        if not self.handle_stage(
            "Archiving tcpdump capture file",
            self.client.execute_command,
            command=f"tar -P -zcvf {os.path.join(self.receiver_dir, 'logs', self.tcpdump_file)}.tar.gz {os.path.join(self.receiver_dir, 'logs', self.tcpdump_file)}"):
            return
        if not self.handle_stage(
            "Downloading tcpdump capture file",
            self.process_manager.run_process,
            "download",
            sftp_client=sftp_client,
            remote_path=f"{os.path.join(self.receiver_dir, 'logs', self.tcpdump_file)}.tar.gz",
            local_path=f"{os.path.join(self.sender_dir, 'logs', self.tcpdump_file)}.tar.gz"):
            return
        if not self.handle_stage(
            "Parsing Test result file",
            self.process_manager.run_process,
            "parse",
            sender_dir=self.sender_dir):
            return

        self.handle_stage(
            "Cleaning up processes",
            self.process_manager.run_process,
            "cleanup",
            processes=[self.tcpdump_pid, self.itgrecv_pid],
            ssh_pass=self.receiver_ssh_pw)
        
        self.client.close()
        self.logger.info("Successfully Test Finish")