import getopt
from scapy.layers.inet import TCP
import sys


# --Globals--
flood = False
flags = {"S": False}
ports = ""
target = ""




#if no port send to 0
#if not flood then print each received packet
# if flood then just spam send

#Starting send port is 2112



def main():
    pass



def usage():
    print("usage: python main.py host [options]")
    print("-h  --help   show this help")
    print("    --flood  sent packets as fast as possible. Don't show replies.")
    print("-S  --syn    set syn flag")
    print("-p  --destport   specify destination port")


def process_args():
    global flood, target
    try:
        opts, args = getopt.getopt(sys.argv[1:], "h8:Sp:", ["help", "flood", "syn", "destport=", "scan"])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)  # will print something like "option -a not recognized"
        sys.exit(2)
    for option, argument in opts:
        if option in ("-h", "--help"):
            usage()
        elif option == "flood":
            flood = True
            print(flood)
        elif option in ("-S", "--syn"):
            flags['S'] = True
            print(flags)
        elif option in ("-p", "--destport"):
            ports= argument
            print(ports)
        elif option in ("-8", "--scan"):
            ports= argument
            print(ports)
        else:
            assert False, "unhandled option"
    if len(args) != 1:
        print("Must specify a single host!")
        sys.exit(1)
    else:
        target = args[0]

if __name__ == "__main__":
    process_args()
    main()




