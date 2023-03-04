import getopt
from scapy.layers.inet import TCP, IP, Ether
from scapy.all import Raw, send
from scapy.volatile import RandShort
import sys


# --Globals--
flood = False
scan = False
flags = "R"
ports = "0"
target = ""


def main():
    if scan:
        # Todo
        print(scan)
    if flood:
        send_flood()
    # Todo
    # send_packet


def send_flood():
    print("In flood mode, no replies will be shown")
    print(flags)
    # Send packet in loop until ctrl+c is pressed
    send(IP(dst=target, ttl=64)
         /TCP(sport=RandShort(), flags=flags, dport=int(ports))/Raw(b"X"*1024), loop=1, verbose=0)
    # Exit
    sys.exit("Exiting!")


def send_packet():
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
        opts, args = getopt.getopt(sys.argv[1:], "h8:Sp:", ["help", "flood", "syn", "destport=", "scan"])
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




