import paramiko

class SSHClient:
    def __init__(self, ip, ssh_user, ssh_pass):
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh_client.connect(ip, username=ssh_user, password=ssh_pass)
        
    def execute_command(self, command, get_output=False):
        stdin, stdout, stderr = self.ssh_client.exec_command(command)
        stdout.channel.recv_exit_status() # 블로킹 호출로 명령 실행 완료 대기
        if get_output:
            return stdout.read().decode().strip(), stderr.read().decode().strip()
        return None, None
    
    def close(self):
        self.ssh_client.close()