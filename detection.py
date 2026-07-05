import scapy.all as scapy
import time
import os
from rich.table import Table
from rich.console import Console

NETWORK = "192.168.178.0/24"

spoof_warnings = []
reported_ips = set()

def create_arp_table():
    arp_reqest = scapy.ARP(pdst=NETWORK)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_reqest 
    answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)[0]
    first_seen = time.strftime("[%H:%M:%S]")

    with open("arp_table.txt", "a", encoding="ascii") as file:
         for sent, received in answered_list: 
            file.write(received.psrc + " " + received.hwsrc + " " + first_seen + " " + first_seen + "\n")
            print("[*]" + received.psrc, "->", received.hwsrc)

def process_packet(packet):
    if scapy.ARP not in packet:
        return

    source_ip = packet[scapy.ARP].psrc
    source_mac =  packet[scapy.ARP].hwsrc
    real_mac = get_mac(source_ip)
    #*print("==========================================")
    #*print("| Source IP: " + source_ip)
    #*print("| Source MAC: " + source_mac)
    #*print("| Vendor: " + scapy.conf.manufdb._get_manuf(source_mac))
    #*print("| Operation type: " + str(packet[scapy.ARP].op))
    #*print("| Time: " + time.strftime("[%H:%M:%S]"))
    #*print("==========================================")

    if real_mac == source_mac:
        update_table(source_ip, source_mac)
    spoof_detection(packet)
    print("\033c", end="")
    display_arp_table()
    display_warnings()

def spoof_detection(packet):
    source_ip = packet[scapy.ARP].psrc
    source_mac =  packet[scapy.ARP].hwsrc
    found = False

    with open("arp_table.txt", "r") as file:
        for line in file:
            parts = line.split()
            ip = parts[0]
            mac = parts[1]

            if ip == source_ip:
                found = True
                if mac != source_mac and packet[scapy.ARP].op == 2:
                    real_mac = get_mac(source_ip)
                    if real_mac and real_mac != source_mac:
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
                    
                        #print("----------------WARNING----------------")
                        #print("[*] TIME: " + time.strftime("[%H:%M:%S]"))
                        #print("[*] MAC-Spoofing (MITM) DETECTED")
                        #print("[*] Target IP: " + source_ip)
                        #print("[*] Real MAC: " + real_mac)
                        #print("[*] Received MAC: " + source_mac)
                        #print("---------------------------------------")
                        #!display_warnings()
                    if real_mac == source_mac:
                        update_table(source_ip, real_mac)
                        reported_ips.discard(source_ip)

                        spoof_warnings[:] = [
                            w for w in spoof_warnings
                            if w["suspicious_ip"] != source_ip
                        ]
                break  
    if not found:
        add_device(source_ip, source_mac)

def get_mac(target_ip):
    #creatign an ARP request with target ip
    arp_reqest = scapy.ARP(pdst=target_ip)
    #creating an Ether frame to broadcast the request with tatget ip
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    #combining via '/'
    arp_request_broadcast = broadcast / arp_reqest 
    #srp is a func that sends/recieves packets on Layer 2
    #sends arp_request_broadcast packet, waits for an answer for 5 sec and returns only answers ([0]) 
    # [0] - answers; [1] unanswered
    answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)[0]
    
    # answered list:

    # [
    # (sent_packet, received_packet),
    # (sent_packet, received_packet),
    # ]
    if answered_list:
        return answered_list[0][1].hwsrc

    return None

def add_device(source_ip, source_mac):
    #*print("---------------Found New Device---------------")
    #*print (source_ip + "->" + source_mac)
    #*print("----------------------------------------------")
    first_seen = time.strftime("[%H:%M:%S]")
    with open("arp_table.txt", "a") as file:
        file.write(source_ip + " " + source_mac + " " + first_seen + " " + first_seen + "\n")

def update_table(source_ip, real_mac):
    last_seen = time.strftime("[%H:%M:%S]")
    with open("arp_table.txt", "r") as file:
        lines = file.readlines()
    with open("arp_table.txt", "w") as file:
        for line in lines:
            ip = line.split()[0]
            first_seen = line.split()[2]
            if ip == source_ip:
                file.write(f"{ip} {real_mac} {first_seen} {last_seen}\n")
            else:
                file.write(line)

def display_arp_table():
    console = Console()
    table = Table(title="ARP Table")
    table.add_column("IP Address", style="cyan", no_wrap=True)
    table.add_column("MAC Address", style="green")
    table.add_column("First Seen", style="yellow")
    table.add_column("Last Seen", style="yellow")

    with open("arp_table.txt", "r") as file:
        for line in file:
            parts = line.strip().split()
            if len(parts) >= 4:
                table.add_row(parts[0], parts[1], parts[2], parts[3])

    console.print(table)

def display_warnings():
    console = Console()
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
    create_arp_table()

    scapy.sniff(
        filter="arp",
        prn = process_packet,
        store=False
    )





