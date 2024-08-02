import paramiko

class SSHClient:
    def __init__(self, ip, ssh_user, ssh_pass):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(ip, username=ssh_user, password=ssh_pass)
        
    def execute_command(self, command, get_output=False):
        stdin, stdout, stderr = self.client.exec_command(command)
        stdout.channel.recv_exit_status() # 블로킹 호출로 명령 실행 완료 대기

        if get_output:
            return stdout.read().decode().strip(), stderr.read().decode().strip()
        
        return None, None
    
    def close(self):
        self.client.close()