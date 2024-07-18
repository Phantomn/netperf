#!/bin/bash

RECEIVER_IP="192.168.11.84"
SSH_USER="phantom"
SSH_PASS="1"
LOG_DIR="logs"
SCAPY_SCRIPT="/home/phantom/syn_storm.py"
TCPDUMP_FILE="capture.pcap"

mkdir -p $LOG_DIR

echo "Starting tcpdump on receiver..."
sshpass -p $SSH_PASS ssh -o StrictHostKeyChecking=no $SSH_USER@$RECEIVER_IP "sudo nohup tcpdump -i any -w $TCPDUMP_FILE > /dev/null 2>&1 &"
if [ $? -ne 0 ]; then
	echo "Failed to start tcpdump on receiver."
	exit 1
fi
echo "tcpdump started successfully."

echo "Starting ITGRecv on receiver..."
sshpass -p $SSH_PASS ssh -o StrictHostKeyChecking=no $SSH_USER@$RECEIVER_IP "/home/phantom/D-ITG-2.8.1-r1023/bin/ITGRecv > itgrecv.log 2>&1 &"
sleep 2
sshpass -p $SSH_PASS ssh -o StrictHostKeyChecking=no $SSH_USER@$RECEIVER_IP "pgrep -f ITGRecv"
if [ $? -ne 0 ]; then
        echo "Failed to start ITGRecv on receiver."
        exit 1
fi
echo "ITGRecv started successfully."

echo "Starting Scapy Syn Storm..."
sudo python3 $SCAPY_SCRIPT > /dev/null 2>&1 &
SCAPY_PID=$!
if [ $? -ne 0 ]; then
        echo "Failed to start Scapy Syn Storm."
        exit 1
fi
echo "Scapy Syn Storm started successfully."

echo "Starting ITGSend for performance measurement..."
ITGSend -T TCP -a $RECEIVER_IP -C 14800 -t 120000 -l $LOG_DIR/sender.log -x $LOG_DIR/receiver.log &
ITG_PID=$!
if [ $? -ne 0 ]; then
        echo "Failed to start ITGSend."
        exit 1
fi
echo "ITGSend started successfully."

echo "Waiting for ITGSend to complete..."
wait $ITG_PID
if [ $? -ne 0 ]; then
        echo "ITGSend encountered an error."
        exit 1
fi
echo "ITGSend completed successfully."

echo "Downloading receiver log file..."
sshpass -p $SSH_PASS scp $SSH_USER@$RECEIVER_IP:$LOG_DIR/receiver.log $LOG_DIR
if [ $? -ne 0 ]; then
        echo "Failed to download receiver log file."
        exit 1
fi
echo "Receiver log file downloaded successfully."

echo "Stopping ITGRecv on receiver..."
sshpass -p $SSH_PASS ssh -o StrictHostKeyChecking=no $SSH_USER@$RECEIVER_IP "pkill ITGRecv"
if [ $? -ne 0 ]; then
        echo "Failed to stop ITGRecv on receiver."
        exit 1
fi
echo "ITGRecv stopped successfully."

echo "Stopping tcpdump on receiver..."
sshpass -p $SSH_PASS ssh -o StrictHostKeyChecking=no $SSH_USER@$RECEIVER_IP "sudo pkill tcpdump"
if [ $? -ne 0 ]; then
	echo "Failed to stop tcpdump on receiver."
	exit 1
fi
echo "tcpdump stopped successfully."

echo "Downloading tcpdump capture file..."
sshpass -p $SSH_PASS scp $SSH_USER@$RECEIVER_IP:$TCPDUMP_FILE $LOG_DIR
if [ $? -ne 0 ]; then
	echo "Failed to download tcpdump capture file."
	exit 1
fi
echo "tcpdump capture file downloaded successfully."


echo "Stopping Scapy Syn Storm..."
kill $SCAPY_PID
if [ $? -ne 0 ]; then
        echo "Failed to stop Scapy Syn Storm."
        exit 1
fi
echo "Scapy stopped successfully."

echo "[+] Test Finished"
echo "=== Receiver Log ==="
ITGDec $LOG_DIR/receiver.log

