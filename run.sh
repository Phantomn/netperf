#!/bin/bash
# expect sshpass
RECEIVER_IP="192.168.11.84"
SSH_USER="phantom"
SSH_PASS="1"
SENDER_DIR="$HOME/netperf"
RECEIVER_DIR="/home/$SSH_USER/netperf"
SCAPY_SCRIPT="syn_storm.py"
TCPDUMP_FILE="capture.pcap"

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to get the current timestamp
get_timestamp() {
    date +"%Y%m%d_%H%M%S"
}
TIMESTAMP=$(get_timestamp)

# Function to print formatted messages
print_msg() {
    local color=$1
    local role=$2
    local binary=$3
    local message=$4
    echo -e "${color}[$TIMESTAMP][$role][$binary] $message${NC}" | tee -a $SENDER_DIR/logs/$TIMESTAMP/execute.log
}

# Function to check the result of the previous command and exit if it failed
check_result() {
    if [ $? -ne 0 ]; then
        print_msg "$RED" "Sender" "Script" "$1"
        cleanup
        exit 1
    fi
}

# Function to run sshpass with SSH commands
ssh_cmd() {
    local CMD=$1
    sshpass -p $SSH_PASS ssh -o StrictHostKeyChecking=no $SSH_USER@$RECEIVER_IP "$CMD"
    check_result "Failed to execute SSH command: $CMD"
}

# Function to run sshpass with SCP commands
ssh_copy() {
    local SRC=$1
    local DEST=$2
    sshpass -p $SSH_PASS scp -o StrictHostKeyChecking=no $SSH_USER@$RECEIVER_IP:$SRC $DEST
    check_result "Failed to copy file from $SRC to $DEST"
}

# Function to run a command with sudo and password
run_sudo_command() {
    local CMD=$1
    $SENDER_DIR/run_sudo_command.sh "$CMD" "$SSH_PASS" "$USER"
}

# Function to clean up processes
cleanup() {
    print_msg "$YELLOW" "Sender" "Script" "Cleaning up processes..."
    if [ -n "$TCPDUMP_PID" ]; then
        ssh_cmd "sudo -k && echo $SSH_PASS | sudo -S kill $TCPDUMP_PID"
    fi
    if [ -n "$ITG_RECV_PID" ]; then
        ssh_cmd "sudo -k && echo $SSH_PASS | sudo -S kill $ITG_RECV_PID"
    fi
    if [ -n "$SCAPY_PID" ]; then
        run_sudo_command "kill $SCAPY_PID"
    fi
    if [ -n "$ITG_PID" ]; then
        kill $ITG_PID
    fi
    print_msg "$YELLOW" "Sender" "Script" "Cleanup completed."
}

# Set trap for SIGINT and script exit
trap cleanup SIGINT EXIT

# Make sure the working directories exist
mkdir -p "$SENDER_DIR/bin" "$SENDER_DIR/codes" "$SENDER_DIR/logs" "$SENDER_DIR/logs/$TIMESTAMP"
ssh_cmd "mkdir -p $RECEIVER_DIR/bin $RECEIVER_DIR/codes $RECEIVER_DIR/logs"

print_msg "$CYAN" "Sender" "tcpdump" "Starting tcpdump on receiver..."
ssh_cmd "sudo -k && echo $SSH_PASS | sudo -S nohup tcpdump -i any -w $RECEIVER_DIR/logs/$TCPDUMP_FILE > /dev/null 2>&1 &"
sleep 2
TCPDUMP_PID=$(sshpass -p $SSH_PASS ssh -o StrictHostKeyChecking=no $SSH_USER@$RECEIVER_IP "pgrep -f 'tcpdump -i any -w $RECEIVER_DIR/logs/$TCPDUMP_FILE' | head -n 1")
check_result "Failed to start tcpdump."
print_msg "$GREEN" "Sender" "tcpdump" "tcpdump started successfully with PID $TCPDUMP_PID"

print_msg "$CYAN" "Sender" "ITGRecv" "Starting ITGRecv on receiver..."
ssh_cmd "nohup $RECEIVER_DIR/bin/ITGRecv > $RECEIVER_DIR/logs/itgrecv.log 2>&1 &"
sleep 2
ITG_RECV_PID=$(sshpass -p $SSH_PASS ssh -o StrictHostKeyChecking=no $SSH_USER@$RECEIVER_IP "pgrep -f ITGRecv" | head -n 1)
check_result "Failed to start ITGRecv."
print_msg "$GREEN" "Sender" "ITGRecv" "ITGRecv started successfully with PID $ITG_RECV_PID"

print_msg "$CYAN" "Sender" "Scapy" "Starting Scapy Syn Storm..."
run_sudo_command "python3 $SENDER_DIR/codes/$SCAPY_SCRIPT" &
SCAPY_PID=$!
sleep 2
SCAPY_PID=$(pgrep -f "python3 $SENDER_DIR/codes/$SCAPY_SCRIPT" | head -n 1)
check_result "Failed to start Scapy Syn Storm."
print_msg "$GREEN" "Sender" "Scapy" "Scapy Syn Storm started successfully with PID $SCAPY_PID"

print_msg "$CYAN" "Sender" "ITGSend" "Starting ITGSend for performance measurement..."
$SENDER_DIR/bin/ITGSend -T TCP -a $RECEIVER_IP -C 14880 -t 120000 -l $SENDER_DIR/logs/$TIMESTAMP/sender.log -x $RECEIVER_DIR/logs/receiver.log &
ITG_PID=$!
check_result "Failed to start ITGSend."
print_msg "$GREEN" "Sender" "ITGSend" "ITGSend started successfully with PID $ITG_PID"

print_msg "$CYAN" "Sender" "ITGSend" "Waiting for ITGSend to complete..."
wait $ITG_PID
check_result "ITGSend encountered an error."
print_msg "$GREEN" "Sender" "ITGSend" "ITGSend completed successfully."

print_msg "$CYAN" "Sender" "SCP" "Downloading receiver log file..."
ssh_copy "$RECEIVER_DIR/logs/receiver.log" "$SENDER_DIR/logs/$TIMESTAMP"
print_msg "$GREEN" "Sender" "SCP" "Receiver log file downloaded successfully."

print_msg "$CYAN" "Sender" "ITGRecv" "Stopping ITGRecv on receiver..."
ssh_cmd "sudo -k && echo $SSH_PASS | sudo -S kill $ITG_RECV_PID"
print_msg "$GREEN" "Sender" "ITGRecv" "ITGRecv stopped successfully."

print_msg "$CYAN" "Sender" "tcpdump" "Stopping tcpdump on receiver..."
ssh_cmd "sudo -k && echo $SSH_PASS | sudo -S kill $TCPDUMP_PID"
print_msg "$GREEN" "Sender" "tcpdump" "tcpdump stopped successfully."

print_msg "$CYAN" "Sender" "SCP" "Downloading tcpdump capture file..."
ssh_cmd "tar -P -zcvf $RECEIVER_DIR/logs/$TCPDUMP_FILE.tar.gz $RECEIVER_DIR/logs/$TCPDUMP_FILE"
ssh_copy "$RECEIVER_DIR/logs/$TCPDUMP_FILE.tar.gz" "$SENDER_DIR/logs/$TIMESTAMP"
print_msg "$GREEN" "Sender" "SCP" "tcpdump capture file downloaded successfully."

print_msg "$CYAN" "Sender" "Scapy" "Stopping Scapy Syn Storm..."
run_sudo_command "kill $SCAPY_PID"
check_result "Failed to stop Scapy Syn Storm."
print_msg "$GREEN" "Sender" "Scapy" "Scapy stopped successfully."

print_msg "$GREEN" "Sender" "Script" "Test Finished"
print_msg "$BLUE" "Sender" "ITGDec" "============================= Receiver Log ============================="
$SENDER_DIR/bin/ITGDec $SENDER_DIR/logs/$TIMESTAMP/receiver.log

# Remove EXIT trap
trap - EXIT
