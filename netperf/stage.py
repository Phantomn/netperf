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
        self.tcpdump_priv = None
        self.suite_priv = None
        self.itgrecv_pid = None
        self.itgrecv_priv = None
        self.itgsend_priv = None
        self.itgsend_pid = None
        
    def handle_stage(self, stage_name, func, *args, **kwargs):
        try:
            result = func(*args, **kwargs)
            self.logger.info(f"{stage_name} completed successfully.")
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
        self.handle_stage(
            "Setting Privilege of tcpdump",
            self.client.execute_command,
            f"echo {self.receiver_ssh_pw} | sudo -S setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump")
        self.tcpdump_priv = self.handle_stage(
            "Getting Privilege of tcpdump",
            self.client.execute_command,
            f"echo {self.receiver_ssh_pw} | sudo -S getcap /usr/bin/tcpdump")
        if not self.tcpdump_priv:
            self.logger.error(f"Failed get tcpdump privilege {self.tcpdump_priv}")
            
        self.suite = Suite(self.sender_nic, self.sender_mac, self.sender_ip, self.receiver_mac, self.receiver_ip)
        if not self.suite:
            return False
        self.suite_priv = self.handle_stage(
            "Getting Privilege of scapy",
            self.process_manager.run_process,
            "priv",
            executable="/usr/bin/python3",
            capabilities="cap_net_raw,cap_net_admin=eip",
            ssh_pass=self.sender_ssh_pw)
        if not self.suite_priv:
            self.logger.error(f"Failed get scapy privilege {self.suite_priv}")
        self.handle_stage(
            "Setting Privilege of ITGRecv",
            self.client.execute_command,
            f"echo {self.receiver_ssh_pw} | sudo -S setcap cap_net_raw,cap_net_admin=eip {self.receiver_dir}/bin/ITGRecv")
        self.itgrecv_priv = self.handle_stage(
            "Setting Privilege of ITGRecv",
            self.client.execute_command,
            f"echo {self.receiver_ssh_pw} | sudo -S getcap {self.receiver_dir}/bin/ITGRecv")
        if not self.itgrecv_priv:
            self.logger.error(f"Failed get ITGRecv privilege {self.itgrecv_priv}")
        else:
            self.logger.info(f"Capabilities for {self.receiver_dir}/bin/ITGRecv: cap_net_raw,cap_net_admin=eip")
        self.itgsend_priv = self.handle_stage(
            "Getting Privilege of ITGSend",
            self.process_manager.run_process,
            "priv",
            executable=f"{self.sender_dir}/bin/ITGSend",
            capabilities="cap_net_raw,cap_net_admin=eip",
            ssh_pass=self.sender_ssh_pw)
        if not self.itgsend_priv:
            self.logger.error(f"Failed get ITGSend Privilege {self.itgsend_priv}")
        
        return True
    
    def run(self):
        if not self.setup():
            self.logger.error("Failed Setup Process")
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
            self.logger.error(f"Failed get tcpdump_pid {self.tcpdump_pid}")
            return
        self.itgrecv_pid = self.handle_stage(
            "Starting ITGRecv on receiver",
            self.process_manager.run_process,
            "itgrecv",
            receiver_dir=self.receiver_dir,
            ssh_pass=self.receiver_ssh_pw)
        if not self.itgrecv_pid:
            self.logger.error(f"Failed get itgrecv_pid {self.itgrecv_pid}")
            return
        self.itgsend_pid = self.handle_stage(
            "Starting ITGSend for performance measurement",
            self.process_manager.run_process,
            "itgsend",
            receiver_ip=self.receiver_ip,
            sender_dir=self.sender_dir,
            receiver_dir=self.receiver_dir,
            timestamp=self.timestamp)
        if not self.itgsend_pid:
            self.logger.error(f"Failed get itgsend_pid {self.itgsend_pid}")
            return
        if not self.handle_stage(
            f"Starting {self.test} Test",
            self.suite.run):
            return
        sftp_client = self.client.open_sftp()
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
            sender_dir=self.sender_dir,
            timestamp=self.timestamp):
            return
        self.handle_stage(
            "Cleaning up processes",
            self.process_manager.run_process,
            "cleanup",
            processes=[self.tcpdump_pid, self.itgrecv_pid],
            ssh_pass=self.receiver_ssh_pw)
        
        self.client.close()
        self.logger.info("Successfully Test Finish")