import pyshark

capture = pyshark.LiveCapture(interface='en0', display_filter="arp")

def print_arp_info(packet):
    #print("ARP Packet: opcode="+packet.arp.opcode+", Sender MAC="+packet.arp.src.hw_mac+", Sender IP="+packet.arp.src.proto_ipv4+", Target MAC="+packet.arp.dst.hw_mac+", Target IP="+packet.arp.dst.proto_ipv4)
    print(packet.arp.proto_ipv4)

capture.apply_on_packets(print_arp_info)

