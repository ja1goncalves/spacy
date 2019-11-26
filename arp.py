import netifaces
from pymongo import MongoClient
import sys
import time
from scapy.layers.l2 import *
from scapy.all import *


def monitor_arp():
    sys.stdout.write(f"\033[1;31;40m Wait all ARP request:\033[00m ")
    loading(3)
    sniff(prn=arp_monitor_callback, filter="arp", store=0)


def arp_monitor_callback(pkt):
    if ARP in pkt and pkt[ARP].op in (1, 2): #who-has or is-at
        return pkt.sprintf("%ARP.hwsrc% -> %ARP.psrc%")


def arp():
    gws = netifaces.gateways()
    gtw_route = gws['default'][netifaces.AF_INET][0]+"/24"

    sys.stdout.write(f"\033[1;30;42m Search addresses in gateway default route: \033[1;36;42m {gtw_route}\033[00m ")
    loading(2)

    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gtw_route), timeout=2)
    ans.summary()

    sys.stdout.write("\033[1;31;40m Wait the listing of addresses\033[00m ")
    loading(4)

    for snd, rcv in ans:
        print(rcv.sprintf(r"%Ether.src% @ %ARP.psrc%"))

    # arp_collection = collection_arp()
    #
    # for snd, rcv in ans:
    #     mac = str(rcv.sprintf(r"%Ether.src%"))
    #     ip = str(rcv.sprintf(r"%ARP.psrc%"))
    #
    #     protocols = arp_collection.find({"mac": mac, "gtw": gtw_route})
    #
    #     if protocols.count() == 0:
    #         print(rcv.sprintf(r"%Ether.src% @ %ARP.psrc% -> NEW"))
    #         arp_collection.insert_one({"ip": ip, "mac": mac, "gtw": gtw_route})
    #     else:
    #         if protocols.count() == 1:
    #             protocol = protocols[0]
    #             if protocol.get('ip') != ip:
    #                 print(rcv.sprintf(r"%Ether.src% @ %ARP.psrc% -> OLD IP: " + protocol.get('ip')))
    #                 arp_collection.update_one({'_id': protocol.get('_id')}, {'$set': {'ip': ip}})
    #             else:
    #                 print(rcv.sprintf(r"%Ether.src% @ %ARP.psrc% -> NOT NEW"))
    #         else:
    #             print(rcv.sprintf(r"%Ether.src% contain multiples IP's"))


def loading(sleep):
    spinner = spinning_cursor()

    for _ in range(sleep*10):
        sys.stdout.write(next(spinner))
        sys.stdout.flush()
        time.sleep(0.1)
        sys.stdout.write('\b')

    sys.stdout.write("\n")


def spinning_cursor():
    while True:
        for cursor in '|/-\\':
            yield cursor


def collection_arp():
    client = MongoClient(port=27017)
    db = client['arp']
    return db.arp


if __name__ == "__main__":
    arp()
    monitor_arp()
