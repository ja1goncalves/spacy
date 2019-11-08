import sys
from scapy.all import *
from scapy.layers.l2 import *


def arp(pdst):
    pdst = pdst+"/24"
    print(f"Search address in {pdst}")
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=pdst), timeout=2)
    ans.summary()

    for snd, rcv in ans:
        print(rcv.sprintf(r"%Ether.src% & %ARP.psrc%\\"))


if __name__ == "__main__":
    default_gtw = input("What your default route gateway? ")
    arp(default_gtw)
