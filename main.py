import pyshark
import sys
import os
from datetime import datetime, timedelta
from scapy.all import * # Install scapy if not already installed
from scapy.layers.dot11 import Dot11
from collections import defaultdict
import logging

logging.basicConfig(level=logging.INFO) # using a logger instead of print statements; should still print to console but can change to go to a file
logger = logging.getLogger(__name__)

ip_mac_mapping = defaultdict(list) # key: ip address, value: list of {mac, timestamp}

TIME_THRESHOLD = 10 # May need to change

# If a disassociation frame is detected, the IP address who is being disconnected gets removed from the IP-MAC map
def remove_disconnected_ip(ip_address):
    if ip_address in ip_mac_mapping:
        del ip_mac_mapping[ip_address]
        logger.info("Removed IP-MAC entry for disconnected IP: %s", ip_address)
    else:
        logger.warning("IP address %s not found in IP-MAC mapping", ip_address)

def check_duplicate_responses(packet):
    ip_address = packet['ARP'].psrc
    mac = packet['ARP'].hwsrc
    timestamp = datetime.now()
    if len(ip_mac_mapping[ip_address]) > 1: # If an IP has more than 1 IP, check if it is duplicate
        last_mac, last_time = ip_mac_mapping[ip_address][-2] # get previous MAC
        if mac != last_mac:
            logger.warning("Potential ARP Spoofing attempt detected: Duplicate ARP responses for IP %s", ip_address)
            return True
    return False

def check_corresponding_request(packet):
    ip_address = packet['ARP'].psrc
    mac = packet['ARP'].hwsrc
    timestamp = datetime.now()

    for req_packet in ip_mac_mapping[ip_address]:
        if req_packet[0] == mac:
            time_diff = (timestamp - req_packet[1]).total_seconds()
            if time_diff > TIME_THRESHOLD:
                logger.warning("Potential ARP Spoofing Attempt Detected: ARP response for IP %s senf after an unreasonable amount of time", ip_address)
                return False
            else:
                logger.info("Valid ARP response")
                return True
        else:
            logger.warning("Potential ARP Spoofing Attempt Detected: No corresponding ARP request for IP %s", ip_address)
            return False

def detect_mac_changes():
    for ip, mac in ip_mac_mapping.items():
        mac_changes = 0
        last_timestamp = None
        for timestamp in mac:
            if last_timestamp is not None and (timestamp[1] - last_timestamp[-1]).total_seconds() <= TIME_THRESHOLD:
                mac_changes += 1
            last_timestamp = timestamp
        
        if mac_changes > 1:
            logger.warning("Potential ARP Spoofing Attempt Detected for IP: %s", ip)
            logger.warning("IP-MAC changes: ")
            for i in range(len(mac)-1):
                logger.warning("%s --> %s (Timestamp: %s)", ip, mac[i][0], mac[i][1])
                logger.warning("%s --> %s (Timestamp: %s)", ip, mac[i+1][0], mac[i+1][1])

def process_packet(packet):
    if 'ARP' in packet:
        arp_packet = packet['ARP']
        ip = arp_packet.psrc
        mac = arp_packet.hwsrc
        timestamp = datetime.now()
        
        if not check_duplicate_responses(packet):
            if check_corresponding_request(packet):
                # Update IP-MAC mapping with the recieved IP and MAC
                ip_mac_mapping[ip].append((mac, timestamp))
        
        detect_mac_changes()
    elif Dot11 in packet:
        if packet.type == 0 and packet.subtype == 0: # check if frame is managment frame
            if packet.subtype in {0x0a, 0x0c}: #check if it is a deauthentication or disassociation frame
                ip = packet[IP].src
                remove_disconnected_ip(ip)



def main():
    #Start live capture over internet, only capturing arp packets
    #TODO possibly pass interface in through command line option
    capture = pyshark.LiveCapture(interface='wlan0', display_filter="(arp or wlan.fc.type_subtype == 10)")
    #Apply function on every packet
    capture.apply_on_packets(process_packet)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\nExiting")
        try:
            sys.exit(130)
        except SystemExit:
            os._exit(130)
