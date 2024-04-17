import re
from collections import Counter
import subprocess
from datetime import datetime, timedelta
import time

#real path of the log file
#'/var/log/snort/snort.alert.fast'

#test path of the log file
with open('/var/log/snort/snort.alert.fast') as file:
    log_path = file.read().strip()


threshold = 1  

time_window = 60
read_log_file=log_path


import re

def extract_data(line):
    time_pattern = r"(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d{6})"
    ip_port_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)"
    
    pattern = time_pattern + r".+\[.+\]\s+\[.+\]\s+.+\s+\{TCP\}\s+" + ip_port_pattern + r" -> " + ip_port_pattern

    match = re.search(pattern, line)
    if match:

        return {
            'time': match.group(1),
            'src_ip': match.group(2),
            'dst_ip': match.group(4),
            'dst_port': match.group(5)
        }
    else:
        return None

def detect_syn_flood(log_file_content, threshold, time_window):
    syn_request_counter = Counter()
    current_time = datetime.now()
    print(f"Current time: {current_time}")
    
    for line in log_file_content.splitlines():
        data = extract_data(line) 

        if data:  
            print(f"Matched log entry: {line}")
  
            time_str = data['time']
            src_ip = data['src_ip']
            dst_ip = data['dst_ip']
            dst_port = data['dst_port']
            print(f"Time: {time_str}, Source IP: {src_ip}, Destination IP: {dst_ip}, Destination Port: {dst_port}")
            
            syn_request_counter[(src_ip, dst_port)] += 1
            if syn_request_counter[(src_ip, dst_port)] >= threshold:
                print(f"Potential SYN Flood detected from {src_ip} to port {dst_port}")
                trigger_defense(src_ip, dst_port)
                print("defense mechanism triggered")
                syn_request_counter[(src_ip, dst_port)] = 0


def trigger_defense(src_ip, dst_port):
    if not src_ip or not dst_port:
        print("Invalid IP or port")
        return
    print(f"Triggering defense mechanism for potential SYN Flood from {src_ip} to port {dst_port}")
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", src_ip, "-p", "tcp", "--dport", dst_port, "--syn", "-j", "DROP"])


while True:
    log_file_content = read_log_file
    if log_file_content:
        print("Reading log file content...")
        detect_syn_flood(log_file_content, threshold, time_window)
    else:
        print("No log file content read, or an error occurred.")


