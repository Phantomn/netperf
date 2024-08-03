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
        self.client = SSHClient(self.receiver_ip, self.receiver_ssh_id, self.receiver_ssh_pw)
        self.process_manager = ProcessManager(self.client)
        self.setup_logging()

        self.sender_nic, self.sender_mac = self.get_nic_info("Sender")
        self.sender_ip = get_nic_ip()
        self.receiver_nic, self.receiver_mac = self.get_nic_info("Receiver", self.client, remote=True)
        self.receiver_dir = self.get_receiver_path()
        self.suite = Suite(self.sender_nic, self.sender_mac, self.sender_ip, self.receiver_mac, self.receiver_ip)
        
        self.pids = {}
        self.privileges = {}
        
        self.prepare_log_directories()

    def setup_logging(self):
        sender_log_path = get_recent_dir(self.sender_dir, self.timestamp)
        Logger.configure(sender_log_path, self.test)
        self.logger = Logger.getLogger()

    def prepare_log_directories(self):
        sender_log_path = get_recent_dir(self.sender_dir, self.timestamp)
        receiver_log_path = get_recent_dir(self.receiver_dir, self.timestamp)
        os.makedirs(sender_log_path, exist_ok=True)
        os.makedirs(receiver_log_path, exist_ok=True)

    def get_nic_info(self, device, client=None, remote=False):
        stage_name = f"Getting NIC and MAC information for {device}"
        nic_info = self.handle_stage(stage_name, get_nic_info, client, remote)
        if nic_info:
            self.logger.info(f"{device} Network info {nic_info[0]}, {self.receiver_ip if remote else self.sender_ip}, {nic_info[1]}")
        return nic_info

    def get_receiver_path(self):
        return self.handle_stage("Getting base for Receiver", get_path, self.client, True)

    def set_privileges(self, name, path, capabilities):
        self.handle_stage(
            f"Setting Privilege of {name}",
            self.client.execute_command,
            f"echo {self.receiver_ssh_pw} | sudo -S setcap {capabilities} {path}"
        )
        privilege = self.handle_stage(
            f"Getting Privilege of {name}",
            self.client.execute_command,
            f"echo {self.receiver_ssh_pw} | sudo -S getcap {path}"
        )
        if privilege:
            self.logger.info(f"Capabilities for {path}: {capabilities}")
        else:
            self.logger.error(f"Failed get {name} privilege")
        self.privileges[name] = privilege

    def setup_privileges(self):
        self.set_privileges("tcpdump", "/usr/bin/tcpdump", "cap_net_raw,cap_net_admin=eip")
        self.set_privileges("ITGRecv", f"{self.receiver_dir}/bin/ITGRecv", "cap_net_raw,cap_net_admin=eip")
        self.set_privileges("scapy", "/usr/bin/python3", "cap_net_raw,cap_net_admin=eip")
        self.set_privileges("ITGSend", f"{self.sender_dir}/bin/ITGSend", "cap_net_raw,cap_net_admin=eip")

    def handle_stage(self, stage_name, func, *args, **kwargs):
        try:
            result = func(*args, **kwargs)
            self.logger.info(f"{stage_name} completed successfully.")
            return result
        except Exception as e:
            self.logger.error(f"Failed to complete {stage_name}: {e}")
            return None

    def run_process(self, process_type, **kwargs):
        pid = self.handle_stage(
            f"Starting {process_type} on receiver",
            self.process_manager.run_process,
            process_type,
            **kwargs
        )
        if pid is None:
            self.logger.error(f"Failed to start {process_type}")
        return pid

    def download_file(self, sftp_client, remote_path, local_path):
        try:
            sftp_client.get(remote_path, local_path)
            self.logger.info(f"Downloaded file from {remote_path} to {local_path}")
        except Exception as e:
            self.logger.error(f"Failed to download file: {e}")

    def archive_and_download(self, sftp_client, file_name):
        if self.handle_stage(
            "Archiving tcpdump capture file",
            self.client.execute_command,
            command=f"tar -P -zcvf {os.path.join(self.receiver_dir, 'logs', file_name)}.tar.gz {os.path.join(self.receiver_dir, 'logs', file_name)}"
        ):
            self.download_file(
                sftp_client,
                f"{os.path.join(self.receiver_dir, 'logs', file_name)}.tar.gz",
                f"{os.path.join(self.sender_dir, 'logs', file_name)}.tar.gz"
            )

    def cleanup_processes(self):
        self.handle_stage(
            "Cleaning up processes",
            self.process_manager.run_process,
            "cleanup",
            processes=[self.pids.get('tcpdump'), self.pids.get('itgrecv')],
            ssh_pass=self.receiver_ssh_pw
        )

    def run(self):
        if not self.setup():
            self.logger.error("Failed Setup Process")
            return

        self.setup_privileges()
        
        self.pids['tcpdump'] = self.run_process(
            "tcpdump",
            iface=self.receiver_nic,
            receiver_dir=self.receiver_dir,
            tcpdump_file=self.tcpdump_file,
            timestamp=self.timestamp
        )

        self.pids['itgrecv'] = self.run_process(
            "itgrecv",
            receiver_dir=self.receiver_dir,
            timestamp=self.timestamp,
            name="itgrecv.log"
        )

        self.pids['itgsend'] = self.run_process(
            "itgsend",
            receiver_ip=self.receiver_ip,
            sender_dir=self.sender_dir,
            receiver_dir=self.receiver_dir,
            timestamp=self.timestamp
        )

        if not self.handle_stage(
            f"Starting {self.test} Test",
            self.suite.run
        ):
            return

        sftp_client = self.client.open_sftp()
        self.download_file(
            sftp_client,
            os.path.join(get_recent_dir(self.receiver_dir, self.timestamp), "receiver.log"),
            os.path.join(get_recent_dir(self.sender_dir, self.timestamp), "receiver.log")
        )
        self.archive_and_download(sftp_client, self.tcpdump_file)

        if not self.handle_stage(
            "Parsing Test result file",
            self.process_manager.run_process,
            "parse",
            sender_dir=self.sender_dir,
            timestamp=self.timestamp
        ):
            return

        self.cleanup_processes()
        
        self.client.close()
        self.logger.info("Successfully Test Finish")
