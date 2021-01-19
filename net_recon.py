#!/usr/bin/python3 

#------------------------------------------
# Name : Prachi Patil
# Student_number : R00194724
# Scripting for cybersecurity assignment 1
# ------------------------------------------

from scapy.all import *
from ipaddress import *
import sys


# User-defined exception if thrown when interface parameter is wrong, which results in ip address to set to 0.0.0.0
# https://www.programiz.com/python-programming/user-defined-exception
class InvalidInterfaceException(Exception):
  pass

# Global Varibale to store ip and mac address
arp_table={}

# Prints help text for tool
def help():
  print ("\nUsage: net_recon.py [ -i interface value ] [-a|-p]")
  print ("\nPerforms active or passive recon on Interface ")
  print ("-i, --iface <interface name> : interface on which active or passive recon needs to be performed")
  print ("\nOptions:")
  print ("-a,   --active       : Active recon ")
  print ("                       Pings all the host on the network and prints ip address who rplies to the request\n")
  print ("-p,   --passive      : Passive recon ")
  print ("                       Prints a table of ipaddress and their mac address on the network.")

# Function to print the list of host responding to Arp request packets.
def print_rply_list(host_rply):
  if len(host_rply)==0:
    print ("\nNo Reply received.")
  else:
    print ("-"*20)
    # aligns the text in center and set the width to 20. [1]
    # https://pyformat.info/#string_trunc_pad (Parametrized formats)
    print ('{:{align}{width}}'.format("Received reply from below hosts",align="^",width=20))
    print ("-"*20)
    # Iterates through the list and prints it.
    for ip in host_rply:
      print ('{:{align}{width}}'.format(ip,align='^',width=20)) 
    print ("-"*20)
 
# Function to check interface and return ip address for correct interface
def get_ip_addr_and_check_interface(interface):
  # Gets IP address from the interface
  # https://scapy.readthedocs.io/en/latest/routing.html#get-local-ip-ip-of-an-interface
  ip_addr = get_if_addr(interface)
  # Ip address is set to 0.0.0.0 if interface is wrong
  if ip_addr == "0.0.0.0":
    # Raise Exception if  ip adddress is set to 0.0.0.0
    raise InvalidInterfaceException
  else:
    return ip_addr

# Function to perform active recon 
def active_recon(interface):
  host_rply=[]
  try:
    # Check interface and stores ip_address of the interface provided by the user
    ip_addr = get_ip_addr_and_check_interface(interface)
    print ("[!]  Assuming mask of /24")
    # subnet mask is hardcoded to 24
    subnet_mask = '/24'
    # ip_network(ip+mask,False): concatenate ip address and subnet mask and strict = False, masks the host bits[1]
    # ip_network(ip+mask,False).hosts() - returns host present in the network [2]
    # [1] https://docs.python.org/3.8/library/ipaddress.html#ipaddress.IPv4Network
    # [2] https://docs.python.org/3.8/library/ipaddress.html#ipaddress.IPv4Network.hosts 
    network_hosts=list(ip_network(ip_addr+subnet_mask,False).hosts())
    # Iterates over each host
    for ip in network_hosts:  
      print ("[+] Pinging the host on ip address:",ip)
      # Sends and recieves(sr) ICMP request and response packets to the ip address from the list
      # timeout(2) : Stops sending packet if no response is received after 2 seconds
      # verbose=0 : Disables printing of packets sent
      # https://stackoverflow.com/questions/38505507/scapy-how-can-i-hide-the-report-of-sendp-sr1-and-just-get-the-final
      # p stores the packet_list of response received and a stores unanswered packets
      # https://scapy.readthedocs.io/en/latest/usage.html#send-and-receive-packets-sr
      # Convert ip address to string in dst field as above ip is of ipaddress.IPv4Address type
      # https://scapy.readthedocs.io/en/latest/usage.html#icmp-ping
      p,a= sr(IP(dst=str(ip))/ICMP(),timeout=2,verbose=0)
      # Each entry in the packet_list has 2 packet, one for ICMP request sent and second for ICMP response received
      for pkt in p:
        # Stores ICMP response in icmp_pkt
        icmp_pkt = pkt[1]
        # ICMP response has src ip address which has responded to the request and is added to global variable host_rply(list)
        host_rply.append(icmp_pkt[IP].src)
    # Print after every host in the network in pinged
    print_rply_list(host_rply)
  # Catches for keyboard interrupt exception and prints the message, and prints the output.
  except KeyboardInterrupt:
    print("\n Process stopped")
    print_rply_list(host_rply)
  # Catches  Invalid Interface Exception
  except InvalidInterfaceException:
    print("[-]  Please check interface value entered. \n")
  # Prints the table after the process is stopped

# Function to  prints ip address if packet is ARP request and stores ip and mac address if it is ARP reply
def passive(pkt):
  # Checks if the packet sniffed has operation bit set as 1, which is ARP request packet
    if pkt[ARP].op==1:
      # if above condition is satisfied, prints the ip address which was pinged 
      print("[+]  Pinged host on ip address: ", pkt[ARP].pdst) 
    # Continue processing if ARP packet has operation bit set to 2, which is ARP Reply packet
    if pkt[ARP].op==2:
      # Gets source IP address of the ARP reply packet
      src_ip = pkt[ARP].psrc
      # gets source mac address from ARP reply packet
      src_mac = pkt[ARP].hwsrc
      # arp_table stores source mac address and source ipaddress in key value pair
      arp_table[src_mac]=src_ip

# Function to perform passive recon
def passive_scan(iface_value):
  try:
    # Check interface value and throw excepption if required
    get_ip_addr_and_check_interface(iface_value)
    print ("[+]  Press Ctrl+C to stop capturing packets.")
    # Start capturing ARP(filter) packets, on interface passed by user and pass the packets to passive function defined above 
    # sniffs traffic on interface,filters ARP traffic and passes one packet at a time to passive function  
    # https://scapy.readthedocs.io/en/latest/usage.html#sniffing
    pkt = sniff(iface=iface_value, prn=lambda pkt : passive(pkt), filter="arp")
    # if no packets are captured then print the message
    if len(pkt)==0:
      print ("\n[!]  No packets were captured")
    # Packets are captured, then print the table
    else:  
      print_table()
  # calls the function to print the table of ip address and mac address
  # Catches InvalidInterfaceException in case the interface value is entered is wrong, checked in line 97
  except InvalidInterfaceException: 
    print("[-]  Please check interface value entered. \n ")

# Function to print table of IP and their corresponding mac address for passive recon
def print_table():
  print ("\n")
  print ("-"*45)
  print ('{:{align}{width}}  |  {:{align}{width}}'.format("IP Address","MAC address",align='^',width=20)) 
  print ("-"*45)
    # Iterates through each key-value(mac-ip address) pair
  for k,v in arp_table.items():
   print ('{:{align}{width}}  |  {:{align}{width}}'.format(v,k,align='^',width=20)) 
  print ("-"*45)

# Function to get iterface value passed by the user
def get_interface_value(arg_list):
    # Checks if the value passed in the arg_list is -i or --iface and stores it
    # https://book.pythontips.com/en/latest/ternary_operators.html
    interface_arg = '-i' if ('-i' in arg_list) else '--iface'
    # Gets poisition of interface switch
    try:
      # First,find the position of i switch in the list, then assuming the argument next to switch(+1 position) is our interface value,
      # it is stored in iface_val 
      iface_val = arg_list[(arg_list.index(interface_arg))+1]
      return iface_val
    # In case only -i switch without any parameter is passed, then print help text 
    except IndexError:
      help()
      sys.exit()
      
#Main function
def main():
    arg_list=[]
    # Reads arguments passed and iterates through the arguments one by one and adds it to  arg_list
    for a in sys.argv:
      arg_list.append(a)
    # Checks for -i/--iface in argument list
    if ('-i' in arg_list) or ('--iface' in arg_list):
      # If true, then calls get_interface_value to fetch interface value
      interface_value = get_interface_value(arg_list)
      # Check for active recon
      if '-a' in arg_list or '--active' in arg_list:
        active_recon(interface_value)
      # Check for passive recon
      elif ('-p' in arg_list)  or ('--passive' in arg_list):
        passive_scan(interface_value)
      # Prints help text if onlu -i/--iface parameter is passed or -i/--iface without -a, -p
      else :
        help()
    # If -i switch not used print help text
    else :
      help()

# Calls main function
if __name__=='__main__':
  main()
  
