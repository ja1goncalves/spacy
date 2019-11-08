import sys
import netifaces
from scapy.all import *
from scapy.layers.l2 import *


def arp():
    gws = netifaces.gateways()
    gtw_route = gws['default'][netifaces.AF_INET][0]+"/24"

    print(f"Search address in gateway default route: {gtw_route}")

    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gtw_route), timeout=2)
    ans.summary()

    for snd, rcv in ans:
        print(rcv.sprintf(r"%Ether.src% & %ARP.psrc%\\"))


if __name__ == "__main__":
    arp()
