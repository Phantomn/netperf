import subprocess
import os
import time
import logging
import glob

logger = logging.getLogger()

class ProcessManager:
    def __init__(self, client):
        self.client = client
    
    def run_process(self, process_type, **kwargs):
        if process_type == "tcpdump":
            command = f"sudo -S nohup tcpdump -i {kwargs['iface']} -w {kwargs['receiver_dir']}/logs/{kwargs['tcpdump_file']} > /dev/null 2>&1 & echo $!"
            stdin, stdout, stderr = self.client.execute_command(f"echo {kwargs['ssh_pass']} | {command}")
            pid = stdout.read().decode().strip()
            time.sleep(2)
        elif process_type == "itgrecv":
            command = f"nohup {kwargs['receiver_dir']}/bin/ITGRecv > {kwargs['receiver_dir']}/logs/itgrecv.log 2>&1 & echo $!"
            stdin, stdout, stderr = self.client.execute_command(command)
            pid = stdout.read().decode().strip()
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
                logger.error(f"Failed to start ITGSend: {e}")
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
                os.path.join(self.get_dir(kwargs['sender_dir']), "receiver.log")
            ]
            try:
                result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
                if result.returncode != 0:
                    raise subprocess.CalledProcessError(result.returncode, command)
                output = result.stdout
                pid = None
                return output
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to start ITGSend: {e}")
                raise            
        else:
            raise ValueError("Unknown process type")
        
        return pid
    
    def get_dir(self, sender_dir):
        subdirs = glob.glob(os.path.join(sender_dir, "logs", "*/"))
        dir_numbers = [int(os.path.basename(os.path.normpath(d))) for d in subdirs if os.path.basename(os.path.normpath(d)).isdigit()]
        
        max_dir_number = max(dir_numbers, default=0)
        new_dir_number = max_dir_number + 1
        new_dir_path = os.path.join(sender_dir, "logs", f"{new_dir_number:04d}")
        
        if os.path.exists(new_dir_path):
            os.makedirs(new_dir_path)
            
        return new_dir_path