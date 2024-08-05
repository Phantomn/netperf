import logging
import os
import subprocess
import glob
import paramiko

# ssh_utils: SSH 관련 기능
class SSHClient:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(SSHClient, cls).__new__(cls)
        return cls._instance

    def __init__(self, ip=None, ssh_user=None, ssh_pass=None):
        if not hasattr(self, 'client'):  # 처음 초기화할 때만 실행
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if ip and ssh_user and ssh_pass:
                self.client.connect(ip, username=ssh_user, password=ssh_pass)
        
    def execute_command(self, command, get_output=False):
        stdin, stdout, stderr = self.client.exec_command(command)
        stdout.channel.recv_exit_status()  # 블로킹 호출로 명령 실행 완료 대기

        if get_output:
            return stdout.read().decode().strip(), stderr.read().decode().strip()
        
        return None, None
    
    def open_sftp(self):
        return self.client.open_sftp()
    
    def close(self):
        self.client.close()

# net_info: 네트워크 정보 관련 기능
def get_nic_ip():
    """기본 네트워크 인터페이스의 IP 주소를 가져옵니다."""
    nic = subprocess.getoutput("ip -o -4 route show to default | awk '{print $5}'")
    ip = subprocess.getoutput(f"ip -o -4 addr show {nic} | awk '{{print $4}}'").split('/')[0]
    return ip

def get_nic_info(client=None, remote_flag=False):
    """네트워크 인터페이스와 MAC 주소를 가져옵니다."""
    if remote_flag and client:
        nic, _ = client.execute_command("ip -o -4 route show to default | awk '{print $5}'", get_output=True)
        mac, _ = client.execute_command(f"cat /sys/class/net/{nic}/address", get_output=True)
    else:
        nic = subprocess.getoutput("ip -o -4 route show to default | awk '{print $5}'")
        mac = subprocess.getoutput(f"cat /sys/class/net/{nic}/address")
    return nic, mac

def get_path(client=None, remote_flag=False):
    """지정된 경로를 검색하여 반환합니다."""
    if remote_flag and client:
        path, _ = client.execute_command("find /home -maxdepth 2 -type d -name 'netperf'", get_output=True)
        return path
    else:
        path = subprocess.getoutput("find /home -maxdepth 2 -type d -name 'netperf'")
        return path

def get_recent_dir(dirs, timestamp):
    """지정된 디렉토리 내에서 가장 최근 디렉토리를 생성하여 반환합니다."""
    subdirs = glob.glob(os.path.join(dirs, "logs", timestamp, "*/"))
        
    dir_numbers = [int(os.path.basename(os.path.normpath(d))) for d in subdirs if os.path.basename(os.path.normpath(d)).isdigit()]

    if not subdirs:
        new_dir_path = os.path.join(dirs, "logs", timestamp, "0000")
    else:
        max_dir_number = max(dir_numbers, default=0)
        new_dir_number = max_dir_number + 1
        new_dir_path = os.path.join(dirs, "logs", timestamp, f"{new_dir_number:04d}") 
            
    os.makedirs(new_dir_path, exist_ok=True)
        
    return new_dir_path

# log_utils: 로그 관련 기능
# ANSI escape sequences for colors
RESET = "\033[0m"
BOLD = "\033[1m"
WHITE = "\033[1;37m"

# Define color codes
text = {
    "magenta": "\033[35m",
    "bold_green": "\033[1;32m",
    "bold_red": "\033[1;31m",
    "bold_blue": "\033[1;34m",
    "bold_yellow": "\033[1;33m",
    "on_red": "\033[41m",
}

# Message type prefixes with colors
_msgtype_prefixes = {
    'debug': [text['bold_red'], 'DEBUG'],
    'info': [text['bold_green'], '*'],
    'warning': [text['bold_yellow'], '!'],
    'error': [text['on_red'], 'ERROR']
}

class ConsoleFormatter(logging.Formatter):
    def format(self, record):
        # Select color and prefix based on log level
        prefix, symbol = _msgtype_prefixes.get(record.levelname.lower(), ["", ""])
        message = f"{WHITE}[{prefix}{symbol}{WHITE}{RESET}] {WHITE}{record.getMessage()}{RESET}"
        return message

class FileFormatter(logging.Formatter):
    DATE_FORMAT = "%Y%m%d %H:%M:%S"

    def format(self, record):
        date = self.formatTime(record, self.DATE_FORMAT)
        prefix, symbol = _msgtype_prefixes.get(record.levelname.lower(), ["", ""])
        message = f"[{date}] {record.getMessage()}"
        return message

class Logger:
    _instance = None
    _loggers = {}
    _default_path = "logs"
    _logger_name = "default"
    _logger_level = logging.INFO
    _configured = False
    
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Logger, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, 'logger'):  # 처음 초기화할 때만 실행
            self.logger = logging.getLogger(Logger._logger_name)
            self.logger.setLevel(Logger._logger_level)
        
            if not self.logger.handlers:
                # Console handler with colored output
                console_handler = logging.StreamHandler()
                console_handler.setFormatter(ConsoleFormatter())
                self.logger.addHandler(console_handler)

                # File handler with timestamp
                if Logger._default_path:
                    try:
                        # Ensure that the directory for the file exists
                        os.makedirs(Logger._default_path, exist_ok=True)

                        # Construct the full file path
                        filename = os.path.join(Logger._default_path, f"{Logger._logger_name}.log")

                        # Create the file if it doesn't exist
                        open(filename, 'a').close()

                        file_handler = logging.FileHandler(filename)
                        file_handler.setFormatter(FileFormatter())
                        self.logger.addHandler(file_handler)
                    except Exception as e:
                        self.logger.error(f"Failed to set up file handler: {e}")

    def debug(self, message):
        self.logger.debug(message)

    def info(self, message):
        self.logger.info(message)

    def warn(self, message):
        self.logger.warning(message)

    def error(self, message):
        self.logger.error(message)

    @classmethod
    def configure(cls, path=None, test="default", level=logging.INFO):
        if cls._configured:
            return
        cls._default_path = path or cls._default_path
        cls._logger_name = test
        cls._logger_level = level
        cls._configured = True
        
    @classmethod
    def getLogger(cls):
        if cls._logger_name not in Logger._loggers:
            Logger._loggers[cls._logger_name] = cls()
        return Logger._loggers[cls._logger_name]
