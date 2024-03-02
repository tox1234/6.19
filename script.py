"""
Author: Ido Shema
Date: 02/03/24
checks if ports are open(listening) for a specific target
"""
from scapy.layers.inet import *
TIMEOUT = 0.5
PORT_START = 20
PORT_END = 1024


def create(target, port):
    """
    Creates a TCP SYN packet and sends it to the target IP address and port.
    :param:target: The target IP address.
    :param:port: The port number to check.
    :return: response of the packet
    """
    ip = IP(dst=target)
    syn = TCP(dport=port, flags="S")
    response = sr1(ip / syn, timeout=0.5, verbose=0)
    return response


def check(target):
    """
    Checks for open ports on the target IP address within the specified port range.
    :param:target: The target IP address.
    :return: list of ports
    """
    lst = []
    for i in range(PORT_START, PORT_END + 1):
        response = create(target, i)
        if response is not None and TCP in response and response[TCP].flags & 0x12:
            lst.append(i)
            print(".", end="")
    print("")
    return lst


def main():
    target = input("Enter the target IP address to scan: ")
    lst = check(target)
    print(lst)


if __name__ == '__main__':
    main()
