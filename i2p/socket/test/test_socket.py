from i2p import socket

from unittest import TestCase

class TestSocket(TestCase):
    
    def test_connect(self):
        """
        test socket connections
        """
        sock = socket.socket()
        sock.connect(("psi.i2p", 80))
        sock.sendall(b'GET / HTTP/1.0\r\n\r\n')
        sock.recv(1024)
        sock.close()

        
    def test_bind(self):
        """
        test socket bind
        """
        ssock = socket.socket()
        ssock.bind(None)
        csock = socket.socket()
        csock.connect(ssock.getsockname())
        asock, addr = ssock.accept()
        asock.close()
        csock.close()
        ssock.close()
        
