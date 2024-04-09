from scapy.all import *

if __name__ == '__main__':

    arp_request = ARP(op=1, pdst="192.168.1.44", hwdst="00:00:00:00:00:00", psrc="192.168.1.30", hwsrc="e8:9f:80:4f:56:97")
    send(arp_request, iface='en0', verbose=False)

    arp_response = ARP(op=2, pdst="192.168.1.30", hwdst="e8:9f:80:4f:56:97", psrc="192.168.1.44", hwsrc="5c:aa:fd:97:c8:72")
    send(arp_response, iface='en0', verbose=False)

    arp_request = ARP(op=1, pdst="192.168.1.44", hwdst="00:00:00:00:00:00", psrc="192.168.1.30", hwsrc="e8:9f:80:4f:56:97")
    send(arp_request, iface='en0', verbose=False)

    #This response will be flagged as an ARP spoofing attempt
    arp_response = ARP(op=2, pdst="192.168.1.30", hwdst="e8:9f:80:4f:56:97", psrc="192.168.1.44", hwsrc="5c:aa:fd:97:c8:73")
    send(arp_response, iface='en0', verbose=False)
