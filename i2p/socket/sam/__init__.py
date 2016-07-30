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
        self.recv = sock.recv
        self.close = sock.close
        self.bind = sock.bind
        self.send = sock.send
        self.connect = sock.connect
        self.sendto = sock.sendto
        self.recvfrom = sock.recvfrom
        self.fileno = sock.fileno
        self.accept = sock.accept
        self.getsockname = sock.getsockname
        self.getpeername = sock.getpeername
        self.makefile = sock.makefile
        self.family = AF_I2P
        self.type = type
        self.proto = proto
        self.gettimeout = sock.gettimeout
        
        
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
