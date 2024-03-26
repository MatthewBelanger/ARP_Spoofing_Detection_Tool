import pyshark
import sys
import os
from datetime import datetime, timedelta

TIME_THRESHOLD = 10 #TODO: Will need to be changed to an appropriate amount of time

arp_requests = []
arp_responses = []

def check_duplicate_responses(packet):
    for saved_pkt in arp_responses:
        if(saved_pkt.arp.src_hw_mac != packet.arp.src_hw_mac and saved_pkt.arp.src_proto_ipv4 == packet.arp.src_proto_ipv4):
            print("\nDUPLICATE ARP RESPONSES DETECTED")
            print("MAC addresses: " + saved_pkt.arp.src_hw_mac + " and " + packet.arp.src_hw_mac + " are both claiming the same IP address: " + packet.arp.src_proto_ipv4 + "\n")
            return False
    return True

def check_corresponding_request(packet):
    if not any(saved_pkt.arp.src_hw_mac == packet.arp.src_hw_mac and saved_pkt.arp.src_proto_ipv4 == packet.arp.src_proto.ipv4 for saved_pkt in arp_responses):
        #loop through requests to find corresponding request
        for req_packets in arp_requests:
            if req_packets.arp.dst_proto_ipv4 == packet.arp.src_proto_ipv4:
                #check if there is already a response to these requests
                if any(resp_packet.arp.src_proto_ipv4 == req_packets.arp.dst_proto_ipv4 for resp_packet in arp_responses):
                    print("An ARP response already exists for the corresponding ARP request for IP: %s", req_packets.arp.dst_proto_ipv4)
                    return False
                else:
                    time_diff = (packet.sniff_time - req_packets.sniff_time).total_seconds()
                    if time_diff > TIME_THRESHOLD:
                        print("This ARP response for IP: %s, was sent after an unreasonable amount of time. Warning: Potential ARP Spoofing Attempt!", packet.arp.dst_proto_ipv4)
                        return False
                    else:
                        print("This is a valid response")
                        return True
                break
        else:
            print("There is no corresponding ARP request for this response. Warning: Potential ARP Spoofing Attempt!")
            return False
    return False

def process_packet(packet):
    #TODO this is here temporarily for debugging, remove later
    print("ARP Packet: opcode="+packet.arp.opcode+", Sender MAC="+packet.arp.src_hw_mac+", Sender IP="+packet.arp.src_proto_ipv4+", Target MAC="+packet.arp.dst_hw_mac+", Target IP="+packet.arp.dst_proto_ipv4)

    if (str(packet.arp.opcode) == "1"):

        #Save the packet
        if(len(arp_requests) >= 100): #Cap at 100 packets TODO: decide if 100 is the right number
            arp_requests.pop(0)
        arp_requests.append(packet)
        return True

    elif(str(packet.arp.opcode) == "2"):

        if
        check_duplicate_responses(packet)
        check_corresponding_request(packet) 

        #Save the packet
        if(len(arp_responses) >= 100): #Cap at 100 packets TODO: decide if 100 is the right number
            arp_responses.pop(0)
        arp_responses.append(packet)
        return True


def main():
    #Start live capture over internet, only capturing arp packets
    #TODO possibly pass interface in through command line option
    capture = pyshark.LiveCapture(interface='en0', display_filter="arp")
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
