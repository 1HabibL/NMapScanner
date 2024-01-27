import nmap

# Create an instance of the PortScanner class from the nmap module
scanner = nmap.PortScanner()

# Print a welcome message
print("Welcome, this is Nmap automation scan tool")
print("<------------------------------------->")

# Get user input for the target IP address
ip_addr = input("Please enter the IP address you want to scan: ")
print("The IP you entered is: ", ip_addr)

# Get user input for the type of scan to perform
resp = input(""" \nPlease enter the type of scan you want to run
             1) SYN ACK SCAN
             2) UDP SCAN
             3) Comprehensive Scan \n""")
print("You have selected option: ", resp)

# Perform actions based on the user's choice
if resp == '1':
   # SYN ACK Scan
   print("Nmap Version: ", scanner.nmap_version()) 
   scanner.scan(ip_addr, '1-1024', '-v -sS')
   print(scanner.scaninfo())
   print("Ip Status: ", scanner[ip_addr].state())
   print(scanner[ip_addr].all_protocols())
   print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif resp == '2':
   # UDP Scan
   print("Nmap Version: ", scanner.nmap_version()) 
   scanner.scan(ip_addr, '1-1024', '-v -sU')
   print(scanner.scaninfo())
   print("Ip Status: ", scanner[ip_addr].state())
   print(scanner[ip_addr].all_protocols())
   print("Open Ports: ", scanner[ip_addr]['udp'].keys())
elif resp == '3':
   # Comprehensive Scan
   print("Nmap Version: ", scanner.nmap_version()) 
   scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
   print(scanner.scaninfo())
   print("Ip Status: ", scanner[ip_addr].state())
   print(scanner[ip_addr].all_protocols())
   print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif resp >= '4':
    # Invalid Option
    print("Invalid Option! Please select a valid number.")