import subprocess

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