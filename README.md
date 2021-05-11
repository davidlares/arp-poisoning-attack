# ARP Poisoning

The `ARP (Address resolution protocol)` is a mechanism that maps an IP to a MAC address (layer 2 MAC - layer 3 IP)

In a few words, the source hosts send a broadcast packet to the whole subnet requesting a reply from the target hosts, once the reply is received, further communications can continue with packets now destined for the MAC address of the target host.

The `Layer 2` to `Layer 3` addressing is temporarily stored in a cache, so this process doesn't need to be repeated
continuously. That's the ARP cache working.

## The ARP process

The `ARP` process can be summarized in two steps:
  1. `Host A` => broadcast to everyone (host B,C, and D)
  2. `Host B` => sends MAC address to host B (saying: that's me) and then, the communication is directly between A and B

## The Cache Poisoning

An attacker send spoofed ARP response messages to the target with the goal of causing the attacker's MAC address to be associated with the IP address of a different host. A successful attack results in messages intended for the spoofed host to be sent to the attacker instead.

This enables the attacker to perform more advanced attacks or simply eavesdrop on communication intended for the victim.

The `arp_reply` is also stored by other hosts, avoiding redundant ARP requests in a network

## The script

With the help of `Scapy` we can craft `ARP packets` based on program inputs. And start the poisoning attack based on execution threads, the packets are sent to the target and the gateway simultaneously until a manual stop is set.

The input values set a target interface for grabbing and intercepting packets, sets the number of packets to capture, and lets you output the traffic into a `pcap` file.

The `sniff()` method from `Scapy` is used for capturing packets, also crafts and sends the packets every 2 seconds.

The `netifaces` library is responsible for the IP - MAC translation.

## How to use it

You'll need a dedicated network interface (controlled preferably) in order to achieve this.

The lab consists of an attacker `Kali machine`, A `Metasploitable2` machine as the victim, and a Ubuntu Server for generating traffic to the poisoned machine.

Run: `python arp-poisoning.py -i [iface] -g [Gateway IP] -o /path/to/file.pcap [Target IP]`

## Requirements

Make sure you have a complete `virtualenv` set up, with the dependencies installed.

Install them with: `pip install -r requirements.txt`

## Credits

 - [David E Lares](https://twitter.com/davidlares3)

## License

 - [MIT](https://opensource.org/licenses/MIT)
