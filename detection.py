import scapy.all as scapy
import time
import re
import os
from rich.table import Table
from rich.console import Console

NETWORK = "192.168.178.0/24"
DISPLAY_RESET = 3
FILE_NAME = "logs_" + time.strftime("%d_%H_%M") + ".txt"
last_display_time = 0

spoof_warnings = []
reported_ips = set()
console = Console()
arp_cache = {}

def create_arp_table():
    arp_request = scapy.ARP(pdst=NETWORK)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request 
    answered_list = scapy.srp(arp_request_broadcast, timeout = 3, verbose = False)[0]
    first_seen = time.strftime("[%H:%M:%S]")

    with open(FILE_NAME, "a", encoding="ascii") as file:
         for sent, received in answered_list: 
            vendor = scapy.conf.manufdb._get_manuf(received.hwsrc)
            file.write(received.psrc + " " + received.hwsrc + " " + first_seen + " " + first_seen + " " + vendor +"\n")
            display_arp_table(console)
            print("[*] Waiting for ARP packets.....")
    load_arp_cache()

def process_packet(packet):
    global last_display_time
    if scapy.ARP not in packet:
        return
    
    spoof_detection(packet)
    now = time.time()

    if(now - last_display_time >= DISPLAY_RESET):
        os.system('clear')
        display_arp_table(console)
        display_warnings(console)
        last_display_time = now

def spoof_detection(packet):
    source_ip = packet[scapy.ARP].psrc
    source_mac =  packet[scapy.ARP].hwsrc
    found = False
    real_mac = arp_cache.get(source_ip)
    with open(FILE_NAME, "r") as file:
        for line in file:
            parts = line.split()
            if len(parts) >= 5:
                ip = parts[0]
            else: continue

            if ip == source_ip:
                found = True

                if packet[scapy.ARP].op == 2:
                    if real_mac == source_mac:
                        update_table(source_ip, source_mac)
                        break  
                    elif real_mac and real_mac != source_mac:
                        if source_ip not in reported_ips:
                            reported_ips.add(source_ip)
                            spoof_warnings.append({
                                "description": "MAC-Spoofing (MITM) DETECTED",
                                "suspicious_ip": source_ip,
                                "real_mac": real_mac,
                                "received_mac": source_mac,
                                "vendor": scapy.conf.manufdb._get_manuf(source_mac),
                                "time": time.strftime("[%H:%M:%S]")
                            })
                        else:
                            for w in spoof_warnings:
                                if w["suspicious_ip"] == source_ip:
                                    w["time"] = time.strftime("[%H:%M:%S]")
                                    break
                break
                    
    if not found:
        if real_mac is None:
            real_mac = get_mac(source_ip)
        if real_mac and source_mac == real_mac:
            add_device(source_ip, source_mac)

def load_arp_cache():
    arp_cache.clear()
    with open(FILE_NAME, "r") as file:
        for line in file:
            parts = line.split()
            if len(parts) >= 2:
                arp_cache[parts[0]] = parts[1]

def get_mac(target_ip):
    arp_request = scapy.ARP(pdst=target_ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request 
    #srp is a func that sends/recieves packets on Layer 2
    #sends arp_request_broadcast packet, waits for an answer for 5 sec and returns only answers ([0]) 
    # [0] - answers; [1] unanswered
    answered_list = scapy.srp(arp_request_broadcast, timeout = 3, verbose = False)[0]
    # answered list:

    # [
    # (sent_packet, received_packet),
    # (sent_packet, received_packet),
    # ]
    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def add_device(source_ip, source_mac):
    first_seen = time.strftime("[%H:%M:%S]")
    vendor = scapy.conf.manufdb._get_manuf(source_mac)
    with open(FILE_NAME, "a") as file:
        file.write(source_ip + " " + source_mac + " " + first_seen + " " + first_seen + " " + vendor + "\n")
    load_arp_cache()

def update_table(source_ip, real_mac):
    with open(FILE_NAME, "r") as file:
        lines = file.readlines()
    with open(FILE_NAME, "w") as file:
        for line in lines:
            parts = line.split()
            if len(parts) >= 5:
                ip = parts[0]
                first_seen = parts[2]
            else: continue

            if ip == source_ip:
                last_seen = time.strftime("[%H:%M:%S]")
                vendor = scapy.conf.manufdb._get_manuf(real_mac)
                file.write(f"{ip} {real_mac} {first_seen} {last_seen} {vendor}\n")
            else:
                file.write(line)
    load_arp_cache()

def display_arp_table(console):
    table = Table(title="ARP Table")
    table.add_column("IP Address", style="cyan", no_wrap=True)
    table.add_column("MAC Address", style="green")
    table.add_column("Vendor: ", style="purple")
    table.add_column("First Seen", style="yellow")
    table.add_column("Last Seen", style="yellow")

    with open(FILE_NAME, "r") as file:
        for line in file:
            parts = line.strip().split()
            if len(parts) >= 5:
                table.add_row(parts[0], parts[1], parts[4], parts[2], parts[3])

    console.print(table)

def display_warnings(console):
    table = Table(title="Spoofing Warnings", title_style="bold red")
    table.add_column("Description", style="red")
    table.add_column("Suspicious IP", style="cyan")
    table.add_column("Real MAC", style="green")
    table.add_column("Received MAC", style="red")
    table.add_column("Vendor", style="yellow")
    table.add_column("Time", style="white")

    for w in spoof_warnings:
        table.add_row(
            w["description"],
            w["suspicious_ip"],
            w["real_mac"],
            w["received_mac"],
            w["vendor"],
            w["time"]
        )

    console.print(table)

if __name__ == "__main__":
    while True:
        print("[*] Enter A Subnet Address")
        NETWORK = input()
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+/\d+", NETWORK):
            break
        print("[-] Invalid format. Example: 192.168.178.0/24")

    create_arp_table()

    scapy.sniff(
        filter="arp",
        prn = process_packet,
        store=False
    )

#thx




