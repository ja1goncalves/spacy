import netifaces
import sys
import time
from scapy.layers.l2 import *
from scapy.all import *
from pymongo import MongoClient
import datetime

cliente_db = MongoClient('localhost', 27017)
banco = cliente_db.teste_database
db = banco.teste_collection

result = db.find({},{ "_id": 0}).sort("MAC")

for x in result:
  print(x)


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
        dado = {
             "MAC": rcv.sprintf(r"%Ether.src%"),
             "IP": rcv.sprintf("%ARP.psrc%"),
             "Data e horário": datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')
         }
        dados = db.insert_one(dado).inserted_id
        print(rcv.sprintf(r"%Ether.src% @ %ARP.psrc%"))


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


if __name__ == "__main__":
    arp()
    monitor_arp()
