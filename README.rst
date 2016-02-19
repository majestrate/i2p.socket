=======
i2p.socket
=======

public domain

requires:

* Python 2.7 or 3.x

* Java I2P 0.9.14 and higher or i2pd 2.4.0 and higher


usage:

.. code::python

  from i2p import socket 

  # regular socket
  sock = socket.socket() 
  sock.connect(("geti2p.net", 80))
  sock.send(b"GET /\r\n\r\n")
  print (sock.recv(1024))
  sock.close()

  # i2p socket
  sock = socket.socket(socket.AF_I2P)
  sock.connect(("i2p-projekt.i2p", 80))
  sock.send(b"GET /\r\n\r\n")
  print (sock.recv(1024))
  sock.close()
