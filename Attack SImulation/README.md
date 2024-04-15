# DDoS Attack and ARP Attack Simulation

In our project, we realized 2 type of attack, DDoS and MITM Attack, which are easy happened in Smart Home. The specific attacks are SYN flood, LAND attack and ARP poisoning. The work based on the Kali Linux, please work in the same environment.

## DDoS Attack simulation
This folder includes two Python scripts designed to simulate two different types of DDoS attacks: SYN Flood and LAND Attack.
### Requirements
Before running these scripts, ensure you have:
- **Python**: Check by running `python3 --version` in your terminal.
- **`hping3`**: Install it on Debian-based systems using `sudo apt-get install hping3`.
- **Administrative privileges**: Needed to perform packet crafting and sending.

### How to RUN

Run the following command in your terminal.

### SYN flood:
```sh
sudo python3 SYN_flood.py <target_ip> <target_port>
```
### Land Attack
```sh
sudo python3 LAND_attack.py <IP_address> <port>
```

## ARP Poisoning (MITM Attack)
The attack simulates the use of a tool for Kali Linux: Ettercap. Ensure successful installation and administrator rights before running.

### How to Implement

1. Select the target device to sniff and the network interface where the gateway is located. 
2. click "Scan for hosts" to scan for active devices on the local network. 
3. Select the IP of the target machineas target 1 and the gateway as target 2. 
4. After that, click on “ARP poisoning” in the “MITM” options and select the “Sniff remote connections” option to start the attack simulation.  