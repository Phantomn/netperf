import subprocess
import os
import glob
import time

def get_nic_info(client, remote_flag=False):
    if remote_flag:
        nic, _ = client.execute_command(client, "ip -o -4 route show to default | awk '{print $5}'", get_output=True)
        mac, _ = client.execute_command(client, f"cat /sys/class/net/{nic}/address", get_output=True)
    else:
        nic = subprocess.getoutput("ip -o -4 route show to default | awk '{print $5}'")
        mac = subprocess.getoutput(f"cat /sys/class/net/{nic}/address")
    return nic, mac

def get_path(client, remote_flag=False):
    if remote_flag:
        path, _ = client.execute_command(client, "find /home -type d -name 'netperf'", get_output=True)
        return path
    else:
        path = subprocess.getoutput("find /home -type d -name 'netperf'")
        return path
    
def get_recent_dir(sender_dir):
    timestamp = time.strftime("%Y%m%d")
    subdirs = glob.glob(os.path.join(sender_dir, "logs", timestamp, "*/"))
    dir_numbers = [int(os.path.basename(os.path.normpath(d))) for d in subdirs if os.path.basename(os.path.normpath(d)).isdigit()]
    
    max_dir_number = max(dir_numbers, default=0)
    new_dir_number = max_dir_number + 1
    new_dir_path = os.path.join(subdirs, f"{new_dir_number:04d}")
    
    if os.path.exists(new_dir_path):
        os.makedirs(new_dir_path)
        
    return new_dir_path