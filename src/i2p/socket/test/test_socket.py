from i2p import socket

from unittest import TestCase

class TestSocket(TestCase):
    
    def test_connect(self):
        """
        test socket connections
        """
        sock = socket.socket()
        sock.connect(("psi.i2p", 80))
        sock.close()

        
    def test_bind(self):
        """
        TODO: implement
        """
