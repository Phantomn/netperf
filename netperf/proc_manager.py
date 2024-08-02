import subprocess
import os
import time
from net_info import get_recent_dir
from parser import Parser
from log_utils import Logger

class ProcessManager:
    def __init__(self, client):
        self.client = client
        self.parser = None
        self.logger = Logger.getLogger()
    
    def run_process(self, process_type, **kwargs):
        if process_type == "tcpdump":
            command = f"sudo -S nohup tcpdump -i {kwargs['iface']} -w {kwargs['receiver_dir']}/logs/{kwargs['tcpdump_file']} > /dev/null 2>&1 & echo $!"
            stdout, stderr = self.client.execute_command(f"echo {kwargs['ssh_pass']} | {command}", True)
            pid = stdout
            time.sleep(2)
        elif process_type == "itgrecv":
            command = f"nohup {kwargs['receiver_dir']}/bin/ITGRecv > {kwargs['receiver_dir']}/logs/itgrecv.log 2>&1 & echo $!"
            stdout, stderr = self.client.execute_command(command)
            pid = stdout
            time.sleep(2)
        elif process_type == "itgsend":
            command = [
                os.path.join(kwargs['sender_dir'], "bin", "ITGSend"),
                "-T", "TCP",
                "-a", kwargs['receiver_ip'],
                "-C", "14880",
                "-t", "120000",
                "-l", os.path.join(kwargs['sender_dir'], "logs", "sender.log"),
                "-x", os.path.join(kwargs['receiver_dir'], "logs", "receiver.log")
            ]
            try:
                result = subprocess.run(command, check=True)
                if result.returncode != 0:
                    raise subprocess.CalledProcessError(result.returncode, command)
                else:
                    time.sleep(2)
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to start ITGSend: {e}")
                raise
            pid = None
        elif process_type == "kill":
            command = f"sudo -S kill {kwargs['pid']}"
            self.client.execute_command(f"echo {kwargs['ssh_pass']} | {command}")
            pid = None
        elif process_type == "download":
            kwargs['sftp_client'].get(kwargs['remote_path'], kwargs['local_path'])
            pid = None
        elif process_type == "cleanup":
            for pid in kwargs['processes']:
                if pid:
                    self.run_process("kill", pid=pid, ssh_pass=kwargs['ssh_pass'])
            pid = None
        elif process_type == "parse":
            command = [
                os.path.join(kwargs['sender_dir'], "bin", "ITGDec"),
                os.path.join(get_recent_dir(kwargs['sender_dir']), "receiver.log")
            ]
            try:
                result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
                if result.returncode != 0:
                    raise subprocess.CalledProcessError(result.returncode, command)
                self.parser = Parser(result.stdout).extract_info()
                pid = None
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to start ITGSend: {e}")
                raise            
        else:
            raise ValueError("Unknown process type")
        
        return pid