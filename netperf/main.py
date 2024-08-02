import argparse
from stage import Stage

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network performance test script.")
    parser.add_argument("sender_ssh_pw", help="SSH password for the sender.")
    parser.add_argument("receiver_ip", help="IP address of the receiver.")
    parser.add_argument("receiver_ssh_id", help="SSH username for the receiver.")
    parser.add_argument("receiver_ssh_pw", help="SSH password for the receiver.")
    parser.add_argument("test", help="Name of the Scapy script to run.")

    args = parser.parse_args()
    stage = Stage(args.sender_ssh_pw, args.receiver_ip, args.receiver_ssh_id, args.receiver_ssh_pw, args.test)
    stage.run()
