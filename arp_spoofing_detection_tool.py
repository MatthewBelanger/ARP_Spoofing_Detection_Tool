import pyshark
import sys
import os

ip_mac_mapping = {} # key: ip address, value:mac

arp_requests = []

# If a disassociation frame is detected, the IP address who is being disconnected gets removed from the IP-MAC map
def remove_disconnected_ip(ip_address):
    if ip_address in ip_mac_mapping:
        del ip_mac_mapping[ip_address]
        print("Removed IP-MAC entry for disconnected IP " + ip_address)
    else:
        print("IP address %s not found in IP-MAC mapping " + ip_address)

def check_corresponding_request(packet):

    for ip_address in ip_mac_mapping:
        if (str(packet.arp.src_proto_ipv4) == ip_address and str(packet.arp.src_hw_mac) != ip_mac_mapping[ip_address]):
            print("Already a mapping in place for this IP address. Warning: Potential ARP Spoofing Attempt!")

    #loop through requests to find corresponding request to this response
    for req_packet in arp_requests:
        if req_packet.arp.dst_proto_ipv4 == packet.arp.src_proto_ipv4:
            arp_requests.remove(req_packet)
            print("Valid request")
            return True
              
    print("There is no corresponding ARP request for this response. Warning: Potential ARP Spoofing Attempt!")
    return False


def process_packet(packet):
    if 'ARP' in packet:    
        #TODO this is here temporarily for debugging, remove later
        #print("ARP Packet: opcode="+packet.arp.opcode+", Sender MAC="+packet.arp.src_hw_mac+", Sender IP="+packet.arp.src_proto_ipv4+", Target MAC="+packet.arp.dst_hw_mac+", Target IP="+packet.arp.dst_proto_ipv4)

        if (str(packet.arp.opcode) == "1"):

            #Save the packet
            arp_requests.append(packet)
            return

        elif(str(packet.arp.opcode) == "2"):

            if(check_corresponding_request(packet)):
                ip = packet.arp.src_proto_ipv4
                mac = packet.arp.src_hw_mac

                # Update IP-MAC mapping with the recieved IP and MAC
                ip_mac_mapping[ip] = mac
            return
        
    if 'wlan' in packet:
        print("WLAN")
        if str(packet.wlan.type) == "0":  # check if frame is managment frame
            if(str(packet.wlan.subtype) == "0x0a"): #check if it is a disassociation frame
                ip = packet.ip.src
                remove_disconnected_ip(ip)
        return


def main():
    #Start live capture over internet, only capturing arp packets
    #TODO possibly pass interface in through command line option

    #capture = pyshark.LiveCapture(interface='en0', display_filter="(arp or wlan.fc.type_subtype == 10)")
    capture = pyshark.LiveCapture(interface='en0')

    #Apply function on every packet
    capture.apply_on_packets(process_packet)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting")
        try:
            sys.exit(130)
        except SystemExit:
            os._exit(130)
