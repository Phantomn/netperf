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
        pid = None
        if process_type == "tcpdump":
            command = f"nohup tcpdump -i {kwargs['iface']} -w {os.path.join(get_recent_dir(kwargs['receiver_dir'], kwargs['timestamp']), kwargs['tcpdump_file'])} > /dev/null 2>&1 & echo $!"
            stdout, stderr = self.client.execute_command(command, True)
            pid = stdout
            time.sleep(2)
        elif process_type == "itgrecv":
            command = f"nohup {kwargs['receiver_dir']}/bin/ITGRecv > {os.path.join(get_recent_dir(kwargs['receiver_dir'], kwargs['timestamp']), kwargs['name'])} 2>&1 & echo $!"
            stdout, stderr = self.client.execute_command(command, True)
            pid = stdout
            time.sleep(2)
        elif process_type == "itgsend":
            command = [
                os.path.join(kwargs['sender_dir'], "bin", "ITGSend"),
                "-T", "TCP",
                "-a", kwargs['receiver_ip'],
                "-C", "14880",
                "-t", "120000",
                "-l", os.path.join(get_recent_dir(kwargs['sender_dir'], kwargs['timestamp']), "sender.log"),
                "-x", os.path.join(get_recent_dir(kwargs['receiver_dir'], kwargs['timestamp']), "receiver.log"),
            ]
            try:
                pid = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                time.sleep(2)
            except Exception as e:
                self.logger.error(f"Failed to start ITGSend: {e}")
                raise
        elif process_type == "kill":
            command = f"kill {kwargs['pid']}"
            self.client.execute_command(command)
            pid = None
        elif process_type == "download":
            self.logger.info(f"Remote Path : {kwargs['remote_path']}")
            self.logger.info(f"Local Path : {kwargs['local_path']}")
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
                os.path.join(get_recent_dir(kwargs['sender_dir'], kwargs['timestamp']), "receiver.log")
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
        elif process_type == "priv":
            executable = os.path.realpath(kwargs['executable'])
            if not executable:
                self.logger.error("No executable provided for 'priv' operation.")
                return None
            try:
                command = f"sudo -S setcap {kwargs['capabilities']} {executable}"
                result = subprocess.run(command, shell=True, input=f"{kwargs['ssh_pass']}\n", text=True, capture_output=True)
                print(result.stderr.strip())
                command = f"sudo -S getcap {executable}"
                result = subprocess.run(command, shell=True, input=f"{kwargs['ssh_pass']}\n", text=True, capture_output=True)
                priv = result.stdout.strip()
                if priv:
                   self.logger.info(f"Capabilities for {executable}: {kwargs['capabilities']}")
                   return priv
                else:
                    self.logger.error("Failed get privilege")
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to capabilities on {executable}: {e}")
            pid = None
        else:
            raise ValueError(f"Unknown process type {process_type}")
        
        return pid