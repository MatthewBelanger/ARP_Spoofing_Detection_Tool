from scapy.all import *

if __name__ == '__main__':

    #TODO change addresses for your WIFI

    #Send first ARP response
    arp_response1 = ARP(op=2, pdst="192.168.1.30", hwdst="e8:9f:80:4f:56:97", psrc="192.168.1.44", hwsrc="5c:aa:fd:97:c8:73")
    send(arp_response1, iface='en0', verbose=False)

    #Send second ARP response that is a 'duplicate' aka same IP different MAC
    arp_response2 = ARP(op=2, pdst="192.168.1.30", hwdst="e8:9f:80:4f:56:97", psrc="192.168.1.44", hwsrc="5c:aa:fd:97:c8:72")
    send(arp_response2, iface='en0', verbose=False)