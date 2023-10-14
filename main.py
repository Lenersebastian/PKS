import arp
import tcp
import icmp
import argparse


def switch_p():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--parameter')
    args = parser.parse_args()

    if args.parameter == "TCP":
        tcp.tcp_f()
        print("vyslo TCP")
    elif args.parameter == "ARP":
        arp.arp_f()
        print("vyslo ARP")
    elif args.parameter == "ICMP":
        icmp.icmp_f()
        print("vyslo ICMP")
    elif args.parameter == "TFTP":
        tftp.tftp()
        print("vyslo TFTP")
    else:
        print("Zle")


if __name__ == "__main__":
    switch_p()


