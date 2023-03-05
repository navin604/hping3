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
flags = "R"
ports = "0"
target = ""

def main():
    #configure_ports()

    if scan:
        # Todo
        port_scan()
    if flood:
        send_flood()
    # Todo
    # send_packet

def send_flood():
    print("In flood mode, no replies will be shown")
    # Send packet in loop until ctrl+c is pressed
    send(IP(dst=target, ttl=64)
         /TCP(sport=RandShort(), flags=flags, dport=int(ports), seq=random.randint(200000000,500000000))
         /Raw(b"X"*1024), loop=1, verbose=0)
    # Exit
    sys.exit(0)

def port_scan():
    no_response = []
    recv_response = []
    ports_arr = []
    for i in range(int(ports.split("-")[0]), int(ports.split("-")[1])+1):
        ports_arr.append(i)
    print(f"{len(ports_arr)} ports to scan!");
    print("+----+-----------+---------+---+-----+-----+-----+");
    print("|port| serv name |  flags  |ttl| id  | win | len |");
    print("+----+-----------+---------+---+-----+-----+-----+");
    for port in ports_arr:
        scan_response = sr1(IP(dst=target, ttl=64)/TCP(sport=RandShort(), dport=port, flags=flags), verbose=0)
        if scan_response is not None:
            if scan_response.haslayer(TCP):
                if scan_response[TCP].flags == 0x12:
                    # Service running
                    print(f"SA from {port}")
                    try:
                        print(socket.getservbyport(port))
                    except OSError:
                        print("No default service")
                    recv_response.append(port)
                    # Close connection
                    sr1(IP(dst=target, ttl=64)/TCP(sport=RandShort(), dport=port, flags="R"),
                        timeout=1, verbose=0)
                elif scan_response[TCP].flags == 0x14:
                    # No service running
                    print(f"RA from {port}")
                    try:
                        print(socket.getservbyport(port))
                    except OSError:
                        print("No default service")
            elif scan_response.haslayer(ICMP):
                if scan_response[ICMP].type == 3 and scan_response[ICMP].code in [1, 2, 3, 9, 10, 13]:
                    # Silently dropped by firewall
                    continue
        else:
            no_response.append(port)



def configure_ports():
    # Todo
    pass

def send_packet():
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
    global flood, target, scan, ports, flags
    try:
        opts, args = getopt.getopt(sys.argv[1:], "h8:Sp:", ["help", "flood", "syn", "destport=", "scan="])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)  # will print something like "option -a not recognized"
        sys.exit(2)
    for option, argument in opts:
        if option in ("-h", "--help"):
            usage()
        elif option == "--flood":
            flood = True
        elif option in ("-S", "--syn"):
            flags = "S"
        elif option in ("-p", "--destport"):
            ports = argument
        elif option in ("-8", "--scan"):
            scan = True
            ports = argument

        else:
            assert False, "unhandled option"
    if len(args) != 1:
        print(args)
        print("Must specify a single host!")
        sys.exit(1)
    else:
        target = args[0]

if __name__ == "__main__":
    process_args()
    main()




