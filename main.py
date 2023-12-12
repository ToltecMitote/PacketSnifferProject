import socket

from scapy.all import *
from scapy.layers.l2 import Ether

# The AF_PACKET specifies the address of the "family" within the socket,
# capturing the packages at the linked air within the ethernet
# The SOCK_RAW is going to capture the raw data on the lower layers of the protocol on the osi-module.
# The socket.ntohs is the protocol that is going to convert the numeric value from the bytes into host bytes
# to represent the package.
# See python 3 library for documentation: https://docs.python.org/3/library/socket.html

sniffer_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

interface = "eth0"
sniffer_socket.bind((interface, 0))

try:
    while True:
        # Receives data from all 65535 ports, you can choose to receive from a specific port
        raw_data, addr = sniffer_socket.recvfrom(65535)
        packet = Ether(raw_data)
        print(packet.summary())
except KeyboardInterrupt:
    sniffer_socket.close()
