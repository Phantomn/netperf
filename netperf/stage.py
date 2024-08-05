import os
import time
from tqdm import tqdm
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
        
        self.sender_nic, self.sender_mac = get_nic_info(None)
        self.sender_ip = get_nic_ip()
        self.receiver_nic, self.receiver_mac = get_nic_info(self.client, True)
        self.receiver_dir = get_path(self.client, True)
        self.suite = Suite(self.sender_nic, self.sender_mac, self.sender_ip, self.receiver_mac, self.receiver_ip)
        
        self.pids = {}
        self.privileges = {}
        
        self.sender_log_path = get_recent_dir(self.sender_dir, self.timestamp)
        if os.path.exists(self.sender_log_path):
            os.makedirs(self.sender_log_path, exist_ok=True)
            
        self.setup_logging()
    
    def setup_logging(self):
        Logger.configure(self.sender_log_path, self.test)
        self.logger = Logger.getLogger()
        
    def handle_stage(self, process_type, func, *args, **kwargs):
        try:
            result = func(*args, **kwargs)
            self.logger.debug(f"{process_type} completed successfully.")
            return result
        except Exception as e:
            self.logger.error(f"Failed to complete {process_type}: {e}")
            return None
   
    def set_privileges(self, name, path, capabilities):
        self.handle_stage(
            f"Setting Privileges of {name}",
            self.client.execute_command,
            f"echo {self.receiver_ssh_pw} | sudo -S setcap {capabilities} {path}")
        
        privilege = self.handle_stage(
            f"Getting Privileges of {name}",
            self.client.execute_command,
            f"echo {self.receiver_ssh_pw} | sudo -S getcap {path}")
        
        if privilege:
            self.logger.info(f"Privileges for {path}: {capabilities}")
        else:
            self.logger.error(f"Failed get {name} privilege")
        self.privileges[name] = privilege
        
    def setup_privileges(self):
        capabilities="cap_net_raw,cap_net_admin=eip"
        tools = ["tcpdump", "ITGRecv", "scapy", "ITGSend"]
        paths = ["/usr/bin/tcpdump", f"{self.receiver_dir}/bin/ITGRecv", "/usr/bin/python3", f"{self.sender_dir}/bin/ITGSend"]
        
        for tool, path in zip(tools, paths):
            self.set_privileges(tool, path, capabilities)
            
    def run_process(self, process_type, **kwargs):
        pid = self.handle_stage(
            f"Starting {process_type} on receiver",
            self.process_manager.run_process,
            process_type,**kwargs)
        if pid is None:
            self.logger.error(f"Failed to start {process_type}")
        return pid
    
    def download_file(self, sftp_client, remote_path, local_path):
        try:
            file_size = sftp_client.stat(remote_path).st_size
            with tqdm(total=file_size, unit='B', unit_scale=True, desc=os.path.basename(local_path)) as progress:
                with sftp_client.file(remote_path, 'rb') as remote_file:
                    with open(local_path, 'wb') as local_file:
                        while True:
                            data = remote_file.read(32768)
                            if not data:
                                break
                            local_file.write(data)
                            progress.update(len(data))
            self.logger.info(f"Downloaded file from {remote_path} to {local_path}")
        except Exception as e:
            self.logger.error(f"Failed to download file: {e}")

    def archive_and_download(self, sftp_client, file_names):
        for file_name in file_names:
            if self.handle_stage(
                f"Archiving file {file_name}",
                self.client.execute_command,
                command=f"tar -C {os.path.join(self.receiver_dir, 'logs')} -zcvf {os.path.join(self.receiver_dir, 'logs', file_name)}.tar.gz {file_name}"):
                self.download_file(
                    sftp_client,
                    f"{os.path.join(self.receiver_dir, 'logs', file_name)}.tar.gz",
                    f"{os.path.join(self.sender_log_path, file_name)}.tar.gz")
                if self.handle_stage(
                    f"Decompress file {file_name}",
                    self.process_manager.run_process,
                    "decomp",
                    path=self.sender_log_path,
                    file_name=file_name):
                    self.logger.error(f"Failed Decompress file {file_name}")
                    self.cleanup_processes()
                
            
    def cleanup_processes(self):
        self.handle_stage(
            "Cleaning up processes",
            self.process_manager.run_process,
            "cleanup",
            processes=[self.pids.get('tcpdump'), self.pids.get('itgrecv')],
            ssh_pass=self.receiver_ssh_pw) 
           
    def run(self):
        self.setup_privileges()
        
        self.pids['tcpdump'] = self.run_process(
            "tcpdump",
            iface=self.receiver_nic,
            receiver_dir=self.receiver_dir,
            tcpdump_file=self.tcpdump_file,
            timestamp=self.timestamp)
        self.pids['itgrecv'] = self.run_process(
            "itgrecv",
            receiver_dir=self.receiver_dir,
            timestamp=self.timestamp,
            name="itgrecv.log")
        self.pids['itgsend'] = self.run_process(
            "itgsend",
            sender_dir=self.sender_dir,
            receiver_ip=self.receiver_ip,
            sender_log_path=self.sender_log_path,
            receiver_dir=self.receiver_dir)
        
        if not self.handle_stage(
            f"Starting {self.test} Test",
            self.suite.run):
            return
        self.cleanup_processes()
        sftp_client = self.client.open_sftp()
        download_file = [
            "receiver.log",
            self.tcpdump_file
        ]
        self.archive_and_download(sftp_client, download_file)

        self.cleanup_processes()
        self.client.close()
        
        if not self.handle_stage(
            f"Parsing {self.test} Test",
            self.process_manager.run_process,
            "parse",
            sender_dir=self.sender_dir,
            sender_log_path=self.sender_log_path):
            return
        
        self.logger.debug("Successfully Test Finish")