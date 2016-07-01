=======
i2p.socket
=======

Requirements:

* Python 2.7 or 3.x

* Java I2P 0.9.14 and higher or i2pd 2.4.0 and higher

Installing:
::
    pip install i2psocket

Or from git:
::
    git clone https://github.com/majestrate/i2p.socket/
    cd i2p.socket
    python setup.py install

Usage:
::
    from i2p import socket 


    
    # i2p socket
    sock = socket.socket()
    sock.connect(("i2p-projekt.i2p", 80))
    sock.send(b"GET /\r\n\r\n")
    print (sock.recv(1024))
    sock.close()
    
    # also works as 'regular' socket
    sock = socket.socket(socket.AF_INET) 
    sock.connect(("geti2p.net", 80))
    sock.send(b"GET /\r\n\r\n")
    print (sock.recv(1024))
    sock.close()
