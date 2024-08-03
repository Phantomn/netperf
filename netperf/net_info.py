import subprocess
import os
import glob

def get_nic_ip():
    nic = subprocess.getoutput("ip -o -4 route show to default | awk '{print $5}'")
    ip = subprocess.getoutput(f"ip -o -4 addr show {nic} | awk '{{print $4}}'").split('/')[0]
    return ip

def get_nic_info(client, remote_flag=False):
    if remote_flag:
        nic, _ = client.execute_command("ip -o -4 route show to default | awk '{print $5}'", get_output=True)
        mac, _ = client.execute_command(f"cat /sys/class/net/{nic}/address", get_output=True)
    else:
        nic = subprocess.getoutput("ip -o -4 route show to default | awk '{print $5}'")
        mac = subprocess.getoutput(f"cat /sys/class/net/{nic}/address")
    return nic, mac

def get_path(client, remote_flag=False):
    if remote_flag:
        path, _ = client.execute_command("find /home -maxdepth 2 -type d -name 'netperf'", get_output=True)
        return path
    else:
        path = subprocess.getoutput("find /home -maxdepth 2 -type d -name 'netperf'")
        return path
    
def get_recent_dir(dirs, timestamp):
    subdirs = glob.glob(os.path.join(dirs, "logs", timestamp, "*/"))
        
    dir_numbers = [int(os.path.basename(os.path.normpath(d))) for d in subdirs if os.path.basename(os.path.normpath(d)).isdigit()]

    if not subdirs:
        new_dir_path = os.path.join(dirs, "logs", timestamp, "0000")
    else:
        max_dir_number = max(dir_numbers, default=0)
        new_dir_number = max_dir_number + 1
        new_dir_path = os.path.join(dirs, "logs", timestamp, f"{new_dir_number:04d}") 
            
    if os.path.exists(new_dir_path):
        os.makedirs(new_dir_path, exist_ok=True)
        
    return new_dir_path