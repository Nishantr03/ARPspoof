import argparse
from scapy.all import ARP, Ether, srp, sniff

def get_mac(ip):
    """
    Get the MAC address of the given IP by sending an ARP request.
    """
    p = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
    result = srp(p, timeout=3, verbose=False)[0]
    return result[0][1].hwsrc

def process(packet):
    """
    Process a sniffed ARP packet to check for ARP spoofing.
    """
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        try:
            real_mac = get_mac(packet[ARP].psrc)
            response_mac = packet[ARP].hwsrc
            if real_mac != response_mac:
                print("YOU ARE BEING ATTACKED")
                return True
        except IndexError:
            pass
    return False

def sniffs(iface):
    """
    Sniff ARP packets on the specified interface and check for attacks.
    """
    print("Starting packet sniffing...")
    sniff(store=False, prn=process, iface=iface, timeout=15)
    print("Sniffing complete. YOU ARE SAFE")

def promiscs(ip):
    """
    Check if a host is in promiscuous mode.
    """
    try:
        t = get_macs(ip)
        print("Promiscuous mode detected!")
    except:
        print("Promiscuous mode not detected.")

def get_macs(ip):
    """
    Test if a host is in promiscuous mode by sending a special ARP packet.
    """
    promisc_test = Ether(dst='01:00:00:00:00:00')/ARP(pdst=ip)
    result = srp(promisc_test, timeout=3, verbose=False)[0]
    return result[0][1].hwsrc

def main():
    parser = argparse.ArgumentParser(description="Network Security Tool")
    
    # Subcommands
    subparsers = parser.add_subparsers(dest="command")

    # Command for ARP sniffing
    sniff_parser = subparsers.add_parser('sniff', help="Sniff network traffic to detect ARP attacks")
    sniff_parser.add_argument('--iface', type=str, required=True, help="Network interface to sniff on (e.g., eth0)")

    # Command for promiscuous mode detection
    promisc_parser = subparsers.add_parser('promisc', help="Detect if a device is in promiscuous mode")
    promisc_parser.add_argument('--ip', type=str, required=True, help="IP address of the host to test")

    # Parse the arguments
    args = parser.parse_args()

    if args.command == 'sniff':
        sniffs(args.iface)
    elif args.command == 'promisc':
        promiscs(args.ip)
    else:
        print("Please specify a valid command (sniff or promisc)")

if __name__ == "__main__":
    main()

