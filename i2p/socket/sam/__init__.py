__doc__ = """
sam3 backend to i2p.socket
"""

from i2p.socket.sam import simple
import socket as pysocket
from socket import *

AF_I2P = simple.AF_I2P

class i2p_socket:

    def __init__(self, type, proto, samaddr, dgramaddr, dgrambind):
        """
        create an i2p socket
        """
        sock = simple.Socket(samaddr, dgramaddr, dgrambind, type)

        # Methods
        self.accept = sock.accept
        self.bind = sock.bind
        self.close = sock.close
        self.connect = sock.connect
        self.fileno = sock.fileno
        self.getpeername = sock.getpeername
        self.getsockname = sock.getsockname
        self.gettimeout = sock.gettimeout
        self.listen = sock.listen
        self.makefile = sock.makefile
        self.recv = sock.recv
        self.recvfrom = sock.recvfrom
        self.recvfrom_into = sock.recvfrom_into
        self.recv_into = sock.recv_into
        self.send = sock.send
        self.sendall = sock.sendall
        self.sendto = sock.sendto
        self.setblocking = sock.setblocking
        self.setsockopt = sock.setsockopt
        self.settimeout = sock.settimeout
        self.shutdown = sock.shutdown

        # Attributes
        self.family = AF_I2P
        self.type = type
        self.proto = proto

        # SAM-specific attributes
        self.getPrivateDest = sock.getPrivateDest


def socket(family=AF_I2P, type=SOCK_STREAM, proto=0, samaddr=('127.0.0.1', 7656), dgramaddr=('127.0.0.1', 7655), dgrambind=('127.0.0.1', 0)):
    """
    wraps socket.socket
    if family is AF_I2P, the socket will use i2p otherwise it will call socket.socket
    """
    if family == AF_I2P:
        return i2p_socket(type, proto, samaddr, dgramaddr, dgrambind)
    else:
        return pysocket.socket(family, type, proto)

def create_connection(address, timeout=60, source_address=None):
    s = socket()
    s.connect(address)
    return s

def getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if host.endswith(".i2p"):
        dest = simple.lookup(host)
        return [(AF_I2P, pysocket.SOCK_STREAM, proto, host, dest)]
    return pysocket.getaddrinfo(host, port, family, type, proto, flags)
