import netifaces
import sys
import time
from scapy.layers.l2 import *
from scapy.all import *


def monitor_arp():
    sys.stdout.write(f"Wait all ARP request: ")
    loading()
    sniff(prn=arp_monitor_callback, filter="arp", store=0)


def arp_monitor_callback(pkt):
    if ARP in pkt and pkt[ARP].op in (1, 2): #who-has or is-at
        return pkt.sprintf("%ARP.hwsrc% -> %ARP.psrc%")


def arp():
    gws = netifaces.gateways()
    gtw_route = gws['default'][netifaces.AF_INET][0]+"/24"

    print(f"Search addresses in gateway default route: {gtw_route}")

    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gtw_route), timeout=2)
    ans.summary()

    sys.stdout.write("Wait the listing of addresses ")
    loading()

    for snd, rcv in ans:
        print(rcv.sprintf(r"%Ether.src% @ %ARP.psrc%"))


def loading():
    spinner = spinning_cursor()

    for _ in range(50):
        sys.stdout.write(next(spinner))
        sys.stdout.flush()
        time.sleep(0.1)
        sys.stdout.write('\b')

    sys.stdout.write("\n")


def spinning_cursor():
    while True:
        for cursor in '|/-\\':
            yield cursor


if __name__ == "__main__":
    arp()
    monitor_arp()
