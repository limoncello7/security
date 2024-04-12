
Configure Network Interface
Run 'ifconfig' to check the current network interface configuration.
If needed, set your network interface to the specific IP range (e.g., '192.168.1.0/24') on 'enp0s3'.

Install Snort using the command 'sudo apt-get install snort -y'.

To allow for all network traffic or set the network interface to promiscuous mode, use 'sudo ip link set enp0s3 promisc on'.
Use 'ls -al /etc/snort' to list the contents of the Snort configuration directory and check the files.
Edit the Snort configuration file '/etc/snort/snort.conf' with 'sudo vim /etc/snort/snort.conf' and change 'home_net' to '192.168.1.0/24'.
Test the Snort configuration with 'sudo snort -T -i enp3s0 -c /etc/snort/snort.conf' and ensure that the rules are read correctly.
Remove Original Snort Rules:
Modify Snort rules as needed. For example, comment out all rules except for local rules to have 0 Snort rules read and 0 detection rules with 'sudo snort -A console -c /etc/snort/snort.conf'.

Test Network Connection
Use 'ping 192.168.1.117' to test the connection to a specific IP address within your network.

Conduct Network Attack Simulation
To simulate a flooding attack for testing purposes, use 'sudo hping3 -c 1000 -d 1200 -S -w 64 -p 80 --flood --rand-source 192.168.1.117' in kali.

active alert test in ubuntu
sudo snort -q -l /var/log/snort -i enp0s3 -A console -c /etc/snort/snort.conf

Then run the code to check the snort.alert.fast file to check attcks, the code will need the password for the user.

