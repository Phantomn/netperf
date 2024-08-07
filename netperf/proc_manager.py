import subprocess
import os
import time
from util import Logger
from parser import Parser

class ProcessManager:
    def __init__(self, client):
        self.client = client
        self.parser = None
        self.logger = Logger.getLogger()

    def run_process(self, process_type, **kwargs):
        pid = None
        if process_type == "tcpdump":
            command = f"nohup tcpdump -i {kwargs['iface']} -w {os.path.join(kwargs['receiver_dir'], 'logs', kwargs['tcpdump_file'])} > /dev/null 2>&1 & echo $!"
            stdout, _ = self.client.execute_command(command, True)
            pid = stdout
            time.sleep(2)
        elif process_type == "itgrecv":
            command = f"nohup {kwargs['receiver_dir']}/bin/ITGRecv > {os.path.join(kwargs['receiver_dir'], 'logs', kwargs['name'])} 2>&1 & echo $!"
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
                "-l", os.path.join(kwargs['sender_log_path'], "sender.log"),
                "-x", os.path.join(kwargs['receiver_dir'], 'logs', "receiver.log")
            ]
            try:
                pid = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                time.sleep(2)
            except Exception as e:
                self.logger.error(f"Failed to start ITGSend: {e}")
                raise
        elif process_type == "kill":
            command = f"kill {kwargs['pid']}"
            try:
                self.client.execute_command(command)
            except Exception as e:
                self.logger.error(f"Failed to kill {kwargs['pid']} {e}")
            pid = None
        elif process_type == "sftp":
            try:
                self.logger.debug(f"Remote Path : {kwargs['remote_path']}")
                self.logger.debug(f"Local Path : {kwargs['local_path']}")
                self.logger.debug(kwargs['action'])
                if kwargs['action'] == "download":          
                    kwargs['sftp_client'].get(kwargs['remote_path'], kwargs['local_path'])
                else:
                    kwargs['sftp_client'].put(kwargs['local_path'], kwargs['remote_path'])
                pid = None
            except Exception as e:
                self.logger.error(f"Failed to {kwargs['action']} file: {e}")
                pid = None
                raise
        elif process_type == "decomp":
            try:
                command=f"tar -C {kwargs['path']} -zxvf {os.path.join(kwargs['path'], kwargs['file_name'])}.tar.gz"
                result = subprocess.run(command, shell=True, text=True, capture_output=True)
                if result.returncode != 0:
                    raise subprocess.CalledProcessError(result.returncode, command)
                pid = None
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to Decompress {kwargs['file_name']}, {e}")
                raise
        elif process_type == "cleanup":
            for pid in kwargs['processes']:
                try:
                    if pid:
                        self.run_process("kill", pid=pid, ssh_pass=kwargs['ssh_pass'])
                except Exception as e:
                    self.logger.error(f"Failed kill to {pid}")
            pid = None
        elif process_type == "parse":
            command = [
                os.path.join(kwargs['sender_dir'], "bin", "ITGDec"),
                os.path.join(kwargs['sender_log_path'], "receiver.log")
            ]
            try:
                result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
                if result.returncode != 0:
                    raise subprocess.CalledProcessError(result.returncode, command)
                self.parser = Parser(result.stdout, kwargs['sender_log_path']).extract_info()
                pid = None
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to parse {kwargs['sender_log_path']}/receiver.log: {e}")
                raise
        elif process_type == "priv":
            executable = os.path.realpath(kwargs['executable'])
            if not executable:
                self.logger.error("No executable provided for 'priv' operation.")
                return None
            try:
                if kwargs['is_remote']:
                    command = f"echo {kwargs['ssh_pass']} | sudo -S setcap {kwargs['capabilities']} {executable}"
                    stdout, _ = self.client.execute_command(command, False)
                    command = f"echo {kwargs['ssh_pass']} | sudo -S getcap {executable}"
                    priv, _ = self.client.execute_command(command, get_output=True)
                else:
                    command = f"sudo -S setcap {kwargs['capabilities']} {executable}"
                    result = subprocess.run(command, shell=True, input=f"{kwargs['ssh_pass']}\n", text=True, capture_output=True)
                    command = f"sudo -S getcap {executable}"
                    result = subprocess.run(command, shell=True, input=f"{kwargs['ssh_pass']}\n", text=True, capture_output=True)
                    priv = result.stdout.strip()
                return priv
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to capabilities on {executable}: {e}")
            pid = None
        else:
            raise ValueError(f"Unknown process type {process_type}")

        return pid
