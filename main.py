import pyshark
import sys
import os

arp_requests = []
arp_responses = []

def check_duplicates(packet):
    for saved_pkt in arp_responses:
        if(saved_pkt.arp.src_hw_mac != packet.arp.src_hw_mac and saved_pkt.arp.src_proto_ipv4 == packet.arp.src_proto_ipv4):
            print("Duplicate detected")

def process_packet(packet):
    print("ARP Packet: opcode="+packet.arp.opcode+", Sender MAC="+packet.arp.src_hw_mac+", Sender IP="+packet.arp.src_proto_ipv4+", Target MAC="+packet.arp.dst_hw_mac+", Target IP="+packet.arp.dst_proto_ipv4)

    if (packet.arp.opcode == 1):

        #Save the packet
        if(arp_requests.__len__ >= 100): #Cap at 100 packets TODO: decide if 100 is the right number
            arp_requests.pop(0)
        arp_requests.append(packet)

    elif(packet.arp.opcode == 2):

        check_duplicates(packet)

        #Save the packet
        if(arp_responses.__len__ >= 100): #Cap at 100 packets TODO: decide if 100 is the right number
            arp_responses.pop(0)
        arp_responses.append(packet)


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