from scapy.all import *
import time

if __name__ == '__main__':

    #Send ARP request
    arp_request = ARP(op=1, pdst="192.168.1.44", hwdst="5c:aa:fd:97:c8:73", psrc="192.168.1.30", hwsrc="e8:9f:80:4f:56:97")
    send(arp_request, iface='en0', verbose=False)

    time.sleep(10)

    #Send ARP response after 10 seconds
    arp_response1 = ARP(op=2, pdst="192.168.1.30", hwdst="e8:9f:80:4f:56:97", psrc="192.168.1.44", hwsrc="5c:aa:fd:97:c8:73")
    send(arp_response1, iface='en0', verbose=False)