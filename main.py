import pyshark

capture = pyshark.LiveCapture(interface='en0', display_filter="arp")
for pkt in capture:
    print(pkt)