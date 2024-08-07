import os
import time
from tqdm import tqdm
from util import SSHClient, get_nic_info, get_path, get_recent_dir, get_nic_ip, Logger
from proc_manager import ProcessManager
from suite import Suite

class Stage:
    def __init__(self, arch, sender_ssh_pw, receiver_ip, receiver_ssh_id, receiver_ssh_pw, test):
        self.arch = arch
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
        os.makedirs(self.sender_log_path, exist_ok=True)

        self.setup_logging()

    def setup_logging(self):
        import logging
        Logger.configure(self.sender_log_path, self.test, logging.DEBUG)
        self.logger = Logger.getLogger()

    def setup(self):
        if not self.receiver_dir:
            self.receiver_dir = f"/home/{self.receiver_ssh_id}/netperf"
            self.client.execute_command(f"mkdir -p {self.receiver_dir}/bin {self.receiver_dir}/logs")
        bin_list = ["ITGDec", "ITGRecv", "ITGLog", "libITG.so"]
        self.cleanup_processes(bin_list)
        for i in bin_list:
            sftp_client = self.client.open_sftp()
            self.sftp_action(sftp_client, "upload", 
                             os.path.join(f"{self.receiver_dir}/bin/{i}"), 
                             f"{self.sender_dir}/bin/arch/{self.arch}/{i}")
            self.client.execute_command(f"echo {self.receiver_ssh_pw} | sudo -S chmod 755 {os.path.join(self.receiver_dir, 'bin', i)}")
        self.setup_privileges()

    def handle_stage(self, process_type, func, *args, **kwargs):
        try:
            result = func(*args, **kwargs)
            self.logger.debug(f"{process_type} completed successfully.")
            return result
        except Exception as e:
            self.logger.error(f"Failed to complete {process_type}: {e}")
            return None

    def set_privileges(self, tools, ssh_pass, is_remote):
        for tool, path in tools.items():
            try:
                privilege = self.run_process(
                    "priv",
                    executable=path,
                    capabilities="cap_net_raw,cap_net_admin=eip",
                    ssh_pass=ssh_pass,
                    is_remote=is_remote)
                if privilege:
                    self.logger.info(f"Privileges set for {tool}({path}): cap_net_raw,cap_net_admin=eip")
                else:
                    raise Exception(f"Privilege setting failed for {tool}")
                self.privileges[tool] = privilege
            except Exception as e:
                self.logger.error(f"Error setting privileges for {tool}: {e}")
                self.privileges[tool] = None
                raise

    def setup_privileges(self):
        remote_tools = {"tcpdump": "/usr/bin/tcpdump","ITGRecv": f"{self.receiver_dir}/bin/ITGRecv"} 
        local_tools = {"scapy": "/usr/bin/python3","ITGSend": f"{self.sender_dir}/bin/ITGSend"}
        try:
            self.set_privileges(remote_tools, self.receiver_ssh_pw, is_remote=True)
            self.set_privileges(local_tools, self.sender_ssh_pw, is_remote=False)
        except Exception as e:
            self.logger.error(f"Failed to set privileges: {e}")

    def run_process(self, process_type, **kwargs):
        pid = self.handle_stage(
            f"Starting {process_type} on receiver",
            self.process_manager.run_process,
            process_type,**kwargs)
        if pid is None:
            self.logger.error(f"Failed to start {process_type}")
        return pid

    def sftp_action(self, sftp_client, action, remote_path, local_path):
        try:
            if action not in ["download", "upload"]:
                self.logger.error(f"Invalid action: {action}")
                return

            if action == "download":
                file_size = sftp_client.stat(remote_path).st_size
                remote_file = sftp_client.file(remote_path, 'rb')
                desc = f"Downloading {os.path.basename(local_path)}"
            else:
                file_size = os.path.getsize(local_path)
                remote_file = sftp_client.file(remote_path, 'wb')
                desc = f"Uploading {os.path.basename(local_path)}"
                
            with open(local_path, 'wb' if action == "download" else "rb") as local_file, remote_file:
                with tqdm(total=file_size, unit='B', unit_scale=True, desc=desc) as progress:
                    while True:
                        data = local_file.read(32768) if action == "upload" else remote_file.read(32768)
                        if not data:
                            break
                        if action == "download":
                            local_file.write(data)
                        else:
                            remote_file.write(data)
                        progress.update(len(data))

            local_file.close()
            remote_file.close()

            if action == "download":
                self.logger.info(f"Downloaded file from {remote_path} to {local_path}")
            else:
                self.logger.info(f"Uploaded file from {local_path} to {remote_path}")

        except Exception as e:
            if action == "download":
                self.logger.debug(f"Failed to {action}: {remote_path} to {local_path} --- {e}")
                raise
            else:
                self.logger.debug(f"Failed to {action}: {local_path} to {remote_path} --- {e}")
                raise

    def archive_and_download(self, sftp_client, file_names):
        for file_name in file_names:
            # Archiving the file on the receiver
            if self.handle_stage(
                f"Archiving file {file_name}",
                self.client.execute_command,
                command=f"tar -C {os.path.join(self.receiver_dir, 'logs')} -zcvf {os.path.join(self.receiver_dir, 'logs', file_name)}.tar.gz {file_name}"
            ):
                # Downloading the archived file
                self.sftp_action(
                    sftp_client, action="download",
                    remote_path=f"{os.path.join(self.receiver_dir, 'logs', file_name)}.tar.gz",
                    local_path=f"{os.path.join(self.sender_log_path, file_name)}.tar.gz"
                )
                # Decompressing the downloaded file
                if self.handle_stage(
                    f"Decompress file {file_name}",
                    self.process_manager.run_process, "decomp",
                    path=self.sender_log_path, file_name=file_name):
                    self.logger.error(f"Failed to decompress file {file_name}")
                    self.cleanup_processes([self.pids.get('tcpdump'), self.pids.get('itgrecv')])
                    raise

    def cleanup_processes(self, processes):
        self.handle_stage(
            "Cleaning up processes",
            self.process_manager.run_process,
            "cleanup",
            processes=processes,
            ssh_pass=self.receiver_ssh_pw) 

    def run(self):
        self.setup()
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

        if not self.handle_stage(f"Starting {self.test} Test", self.suite.run):
            self.cleanup_processes([self.pids.get('tcpdump'), self.pids.get('itgrecv')])
            return

        self.cleanup_processes([self.pids.get('tcpdump'), self.pids.get('itgrecv')])
        sftp_client = self.client.open_sftp()
        download_file = ["receiver.log", self.tcpdump_file]
        self.archive_and_download(sftp_client, download_file)

        self.cleanup_processes([self.pids.get('tcpdump'), self.pids.get('itgrecv')])
        self.client.close()

        if not self.handle_stage(
            f"Parsing {self.test} Test",
            self.process_manager.run_process,
            "parse",
            sender_dir=self.sender_dir,
            sender_log_path=self.sender_log_path):
            return

        self.logger.debug("Successfully Test Finish")
