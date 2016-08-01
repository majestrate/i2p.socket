#
# public domain
#
__doc__ = """
simple sam i2p socket implemenation
"""

from i2p import datatypes
from enum import Enum

import collections
import errno
import logging
import os
import string
import random
import socket as pysocket

from contextlib import wraps

# Address family for i2p
# TODO: fix this
AF_I2P = pysocket.AF_INET

_defaultSAMAddr = ('127.0.0.1', 7656)

class State(Enum):
    """
    state of a sam socket
    """
    
    Initial = 0
    """
    we are not connected to anything, initial state
    """
    
    Established = 1
    """
    we have established a session with sam
    """
    
    Ready = 2
    """
    we are ready to do stuff
    """
    
    Connecting = 3
    """
    we are connecting or binding
    """
    
    Running = 4
    """
    we are connected or bound
    """
    
    Closing = 5
    """
    closing all connections
    """
    
    Closed = 6
    """
    sam connection closed entirely
    """    
    
    Error = 7
    """
    an error occured
    """
    
class SAM:
    """
    decorator constants
    """
    SOCK_STREAM = pysocket.SOCK_STREAM #datatypes.I2CPProtocol.STREAMING
    SOCK_DGRAM = pysocket.SOCK_DGRAM #datatypes.I2CPProtocol.DGRAM
    SOCK_RAW = pysocket.SOCK_RAW #datatypes.I2CPProtocol.RAW

def randnick(l):
    nick = ''
    for n in range(l):
        nick += random.choice(string.ascii_letters)
    return nick
    
def _sam_readline(sock, partial=''):
    """
    read a line from a sam control socket
    """
    response = bytearray()
    finished = True
    while True:
        try:
            c = sock.recv(1)
            if c:
                if c == b'\n':
                    break
                response += c
            else:
                break
        except pysocket.error as err:
            if err.args[0] != errno.EWOULDBLOCK:
                raise
            finished = False
            break
    return partial+response.decode('ascii'), finished

SamReply = collections.namedtuple('SamReply', ['cmd', 'opts'])


def _sam_parse_reply(line):
    """
    parse a reply line into a dict
    """
    opts = dict()
    parts = line.split(' ')

    for part in parts[2:]:
        if '=' in part:
            idx = part.index('=')
            k = part[:idx]
            v = part[1+idx:]
            opts[k] = v
    return SamReply(parts[0], opts)

def _sam_cmd(sock, line):
    """
    do a sam command on a socket
    :returns result:
    """
    line = bytearray(line, 'ascii') + b'\n'
    sock.send(line)
    _line, _finished = _sam_readline(sock)
    return _sam_parse_reply(_line)

class _WrappedPySocket(object):
    """
    a native python socket wrapped to expose i2p addreses instead of ip addresses
    """
    
    def __init__(self, pysock, localdest, remotedest):
        self.getpeername = lambda : remotedest
        self.getsockname = lambda : localdest
        self.get_inheritable = lambda : False
        self.family = AF_I2P
        for attr in ('type', 'proto', 'send', 'recv', 'sendall', 'sendfile', 'fileno', 'close', 'shutdown', 'detach', 'makefile', 'setsockopt', 'getsockopt', 'setblocking', 'settimeout'):
            if hasattr(pysock, attr):
                setattr(self, attr, getattr(pysock, attr))
        
class Socket(object):
    """
    base of all sam socket objects
    """

    _log = logging.getLogger("i2p.socket.sam.simple.BaseSocket")
    _dest_cache = dict()

    def samState(*states):
        def f(func):
            def check_state(self, *args_inner, **kwargs_inner):
                if self._state in states:
                    return func(self, *args_inner, **kwargs_inner)
                else:
                    raise Exception("invalid socket state: {}".format(self._state))
            return check_state
        return f

    def samType(*types):
        def f(func):
            def check_type(self, *args, **kwargs):
                if self.type in types:
                    return func(self, *args, **kwargs)
                else:
                    raise Exception("invalid socket type: {}".format(self.type))
            return check_type
        return f

    def samConnect(func):
        def check_connect(self, *args, **kwargs):
            if self._samSocket is None:
                self._log.info("connecting to sam")
                # we are not connected
                samSocket = pysocket.socket()
                samSocket.setsockopt(pysocket.IPPROTO_TCP, pysocket.SO_KEEPALIVE, 1)
                try:
                    # connect
                    samSocket.connect(self._samAddr)
                    # do handshake
                    self._samHandshake(samSocket)
                except pysocket.timeout as ex:
                    raise ex
                except pysocket.error as ex:
                    raise ex
                else:
                    self._samSocket = samSocket
            return func(self, *args, **kwargs)
        return check_connect
    
    def __init__(self, samaddr, dgramAddr, dgramBind, socketType):
        """
        Internal use ONLY currently, do not use externally
        """
        if samaddr:
            self._samAddr = samaddr
            self._samDgramAddr = dgramAddr
            self._dgram_bind = dgramBind
            self._samSocket = None
            self._data_sock = None
            self._state = State.Initial
            self._deferred_socket_actions = list()
            self._blocking_flag = 1 # Default blocking
            self._pending_accept = None
            self.type = socketType
            self.dest = None
            self.socketname = None
        else:
            raise ValueError("samaddr must not be None")

    
        
        
                
    def _samHandshake(self, sock):
        """
        handshake with sam via a socket.socket instance
        """
        #TODO: sam versions
        repl = _sam_cmd(sock, 'HELLO VERSION MIN=3.0 MAX=3.2')
        if repl.opts['RESULT'] == 'OK':
            self._state = State.Established
        else:
            self._state = State.Error
            raise pysocket.error(errno.ENOTCONN, "failed to handshake with SAM: {}".format(repl.opts["RESULT"]))
        
        
    @samConnect
    @samState(State.Established)
    @samType(SAM.SOCK_STREAM)
    def connect(self, addr, socketname=None, **i2cpOptions):
        """
        connect to a remote endpoint
        :param addr: the remote endpoint to connect to, either a destinatio/name or a (destination/name, port) tuple
        :param socketname: socketname of the destination to connect with, None to use a transient destination
        :param i2cpOptions: additional i2cp options to pass into sam
        """
        self._log.info('connect')
        if socketname is None:
            # bind ephemeral session
            nickname = randnick(7)
            self.bind(None, nickname, **i2cpOptions)
        else:
            # use existing session
            nickname = socketname

        # TODO: specfify i2p ports
        
        if isinstance(addr, tuple):
            addr = addr[0]
        dest = self.lookup(addr)
        # connect out
        self._data_sock = pysocket.socket()
        self._data_sock.connect(self._samAddr)
        # handshake
        # TODO: versions
        repl = _sam_cmd(self._data_sock, 'HELLO VERSION MIN=3.0 MAX=3.2')
        if repl.opts["RESULT"] == "OK":
            # handshake good
            cmd = 'STREAM CONNECT ID={} DESTINATION={} SILENT=false'.format(nickname, dest.base64())
            repl = _sam_cmd(self._data_sock, cmd)
            if repl.opts["RESULT"] == "OK":
                self._state = State.Running
                # apply deferred
                self._apply_defered_socket_props(self._data_sock)
                # connect okay
                return
        # TODO: raise correct exceptions for error messages
        # either handshake fail or stream connect fail
        raise pysocket.error(errno.EHOSTUNREACH, "cannot connect to {}: {}".format(addr, repl))

    def getsockname(self):
        if self.dest:
            return self.dest.to_public()

    def getpeername(self):
        return self._peer

    def _apply_defered_socket_props(self, sock):
        """
        apply defered socket actions
        """
        # execute each defered action
        for action in self._deferred_socket_actions:
            action(sock)
        # reset actions
        self._deferred_socket_actions = list()
    
    @samConnect
    @samType(SAM.SOCK_STREAM)
    def listen(self, n=0):
        return

    @samConnect
    @samState(State.Established)
    @samType(SAM.SOCK_STREAM, SAM.SOCK_DGRAM)
    def bind(self, keyfile, nickname=None, **i2cpOptions):
        """
        bind to an address
        :param keyfile: the file containing the private keys to use or None to not store
        :param nickname: the nickname to use for tunnels or None for random decided by sam
        :param i2cpOptions: additional i2cp options to pass into sam
        """
        if nickname is None:
            nickname = randnick(8)
        self._state = State.Connecting
        if self.type == SAM.SOCK_STREAM:
            style = "STREAM"
        elif self.type == SAM.SOCK_DGRAM:
            style = "DATAGRAM"
            self._dgram_sock = pysocket.socket(type=pysocket.SOCK_DGRAM)
            self._dgram_sock.bind(self._dgram_bind)
            port = self._dgram_sock.getsockname()[1]
            i2cpOptions["HOST"] = self._dgram_bind[0]
            i2cpOptions["PORT"] = port
            # apply deferred options
            self._apply_defered_socket_props(self._dgram_sock)
        else:
            # TODO: implement
            style = "RAW"
            
        _keys = 'TRANSIENT'
        if keyfile:
            if isinstance(keyfile, str):
                if os.path.exists(keyfile):
                    with open(keyfile, 'rb') as f:
                        self.dest = datatypes.Destination(raw=f, private=True)
                        _keys = self.dest.base64()
            elif hasattr(keyfile, 'read'):
                self.dest = datatypes.Destination(raw=keyfile, private=True)
                _keys = self.dest.base64()
        cmd = 'SESSION CREATE STYLE={} DESTINATION={} ID={}'.format(style, _keys, nickname)

        for opt in i2cpOptions:
            cmd += " {}={}".format(opt, i2cpOptions[opt])

        repl = _sam_cmd(self._samSocket, cmd)

        if repl.opts['RESULT'] == 'OK':
            _keys = repl.opts['DESTINATION']
            if self.dest is None:
                self.dest = datatypes.Destination(raw=_keys, b64=True, private=True)
                if keyfile:
                    data = self.dest.serialize(priv=True)
                    if isinstance(keyfile, str):
                        with open(keyfile, 'wb') as f:
                            f.write(data)
                    elif hasattr(keyfile, "write"):
                        keyfile.write(data)
            self.socketname = nickname
            # TODO: do we really want to do this?
            self._apply_defered_socket_props(self._samSocket)
            self._state = State.Ready
        else:
            self._state = State.Error
            # TODO: different types of errors for different types of results from sam
            raise pysocket.error(errno.EADDRNOTAVAIL, "failed to bind destination with i2p: {}".format(repl.opts["RESULT"]))
                                                                                                       

    @samState(State.Ready)
    @samType(SAM.SOCK_STREAM)
    def accept(self):
        # TODO: raise appropriate errors
        if not self._pending_accept:
            # Handle case where we are being used inside gevent
            sock = None
            try:
                from gevent import monkey
                if monkey.is_object_patched('socket', 'socket'):
                    sock = monkey.get_original('socket', 'socket')()
            except:
                pass
            if not sock:
                sock = pysocket.socket()
            # connect to sam
            sock.connect(self._samAddr)
            # say hello
            repl = _sam_cmd(sock, 'HELLO VERSION MIN=3.0 MAX=3.2')
            if repl.opts["RESULT"] != "OK":
                raise pysocket.error(errno.ENOTCONN, "failed to accept: %s" % repl.opts['RESULT'])
            # send command
            cmd = 'STREAM ACCEPT ID={} SILENT=false'.format(self.socketname)
            repl = _sam_cmd(sock, cmd)
            if repl.opts['RESULT'] != 'OK':
                raise pysocket.error(errno.ENOTCONN, "failed to accept: %s" % repl.opts['RESULT'])
            sock.setblocking(self._blocking_flag)
            self._pending_accept = (sock, '')
        sock, partialDest = self._pending_accept
        # read destination for inbound
        dest, _finished = _sam_readline(sock, partialDest)
        if not _finished:
            self._pending_accept = (sock, dest)
            raise pysocket.error(errno.EWOULDBLOCK, "waiting for client to connect")
        self._pending_accept = None
        # parse destination
        dest = datatypes.Destination(raw=dest, b64=True)
        # cache b32 address
        self._dest_cache[dest.base32()] = dest
        # override socket functions
        sock = _WrappedPySocket(sock, self.dest, dest)
        # return socket
        return sock, dest

    @samState(State.Running)
    @samType(SAM.SOCK_STREAM)
    def send(self, data, flags=0):
        """
        send to remote endpoint we are connected to
        :param data: bytearray of data
        :return count:
        """
        return self._data_sock.send(data, flags)
        
    @samState(State.Running)
    @samType(SAM.SOCK_STREAM)
    def sendall(self, data, flags=0):
        """
        send to remote endpoint we are connected to until done or error
        :param data: bytearray of data
        :return None:
        """
        return self._data_sock.sendall(data, flags)

    @samState(State.Running)
    @samType(SAM.SOCK_STREAM)
    def recv(self, nbytes, flags=0):
        """
        recv bytes from endpoint we are connected to
        :param nbytes: number of bytes
        :return bytearry containing <= n bytes:
        """
        return self._data_sock.recv(nbytes, flags)

    @samState(State.Running)
    @samType(SAM.SOCK_STREAM)
    def recv_into(self, buffer, nbytes=None, flags=0):
        """
        recv bytes from endpoint we are connected into buffer
        :param buffer: buffer to recv into
        :param nbytes: number of bytes
        :return bytearry containing <= n bytes:
        """
        return self._data_sock.recv_into(buffer, nbytes, flags)

    
    
    @samState(State.Running, State.Ready)
    @samType(SAM.SOCK_DGRAM, SAM.SOCK_RAW)
    def sendto(self, data, address):
        """
        send to remote endopoint udp style
        :param buff: bytearray
        :return count:
        """
        # TODO: SAM 3.3
        port = 0
        if isinstance(address, tuple):
            address = address[0]
            port = address[1]
        remote_dest = self.loopkup(address)
        if remote_dest:
            dgram = bytearray()
            dgram += b"3.0 "
            dgram += self.socketname.encode('ascii') + b" "
            dgram += remote_dest.encode('ascii') + b"\n"
            dgram += data
            return self._dgram_sock.sendto(dgram, self._samDgramAddr)
        else:
            # drop becasue we don't have the address known
            pass
            
    @samState(State.Running, State.Ready)
    @samType(SAM.SOCK_DGRAM, SAM.SOCK_RAW)
    def recvfrom(self, nbytes, flags=0):
        """
        recv bytes from a remote sender
        :param nbytes: number of bytes to recv max
        :return (data, addressInfo):
        """
        data, addr = self._dgram_sock.recvfrom(nbytes)
        if addr == self._samDgramAddr:
            # only accept packets from the sam udp address
            idx = data.index(b'\n')
            return datatypes.Destination(raw=data[:idx], b64=True), bytearray(data[1+idx:])
        else:
            self._log.warn("invalid source address for sam packet {}".format(addr))

    @samState(State.Running, State.Ready)
    @samType(SAM.SOCK_DGRAM, SAM.SOCK_RAW)
    def recvfrom_into(self, buffer, nbytes=None, flags=0):
        """
        recv bytes from a remote sender
        :param buffer: buffer to recv into
        :param nbytes: number of bytes to recv max
        :return (nbytes, addressInfo):
        """
        if nbytes is None:
            nbytes = len(buffer)
        data, addr = self._dgram_sock.recvfrom(buffersize)
        if addr == self._samDgramAddr:
            # only accept packets from the sam udp address
            idx = data.index(b'\n')
            payload = data[1+idx:]
            l = buffer.write(payload)
            return l, datatypes.Destination(raw=bytearray(data[:idx]), b64=True)
        else:
            self._log.warn("invalid source address for sam packet {}".format(addr))

    
            
    def fileno(self):
        if self.type == SAM.SOCK_STREAM:
            if self._samSocket:
                return self._samSocket.fileno()
            else:
                return self._data_sock.fileno()
        elif self.type == SAM.SOCK_DGRAM:
            return self._dgram_sock.fileno()
        
    @samState(State.Running)
    def shutdown(self, flag):
        if self.type == SAM.SOCK_DGRAM:
            return self._dgram_sock.shutdown(flag)
        elif self.type == SAM.SOCK_STREAM:
            if self._samSocket:
                return self._samSocket.shutdown(flag)
            else:
                return self._data_sock.shutdown(flag)

    @samState(State.Running, State.Established, State.Ready)
    def close(self):
        """
        close the connection
        """
        self._state = State.Closing
        if self._samSocket is not None:
            self._samSocket.close()
        if self.type == SAM.SOCK_DGRAM:
            self._dgram_sock.close()
        elif self.type == SAM.SOCK_STREAM and self._data_sock is not None:
            self._data_sock.close()

        self._state = State.Closed
        
    def lookup(self, name):
        """
        look up a name
        :param name: a name or b32 address
        :returns an i2p.datatypes.Destination instance:
        """
        if isinstance(name, datatypes.Destination):
            # if it's already a destination return it :p
            return name
        # check cache
        if name in self._dest_cache:
            # cache hit
            return self._dest_cache[name]
        # cache miss, do lookup
        # create new socket for lookup
        sock = pysocket.socket()
        try:
            sock.connect(self._samAddr)
            self._samHandshake(sock)
        except pysocket.timeout as ex:
            raise ex
        except pysocket.error as ex:
            raise ex
        else:
            # do lookup
            repl = _sam_cmd(sock, "NAMING LOOKUP NAME={}".format(name))
            # close socket as it is not needed anymore
            sock.close()
            if 'VALUE' in repl.opts:
                dest = datatypes.Destination(raw=repl.opts['VALUE'], b64=True)
                if not name.endswith(".b32.i2p"):
                    # cache name as it's not a b32 address
                    self._dest_cache[name] = dest                    
                # cache base32 address
                self._dest_cache[dest.base32()] = dest
                return dest
            else:
                # failed to lookup
                raise pysocket.herror(errno.EAGAIN, "name not resolved: {}".format(name))

    def settimeout(self, value):
        if value is None:
            self._blocking_flag = 1
        elif value == 0.0:
            self._blocking_flag = 0
        sock = None
        if self.type == SAM.SOCK_STREAM:
            sock = self._data_sock
        elif self.type == SAM.SOCK_DGRAM:
            sock = self._dgram_sock
        elif self._samSocket is not None:
            sock = self._samSocket
        if sock:
            sock.settimeout(value)
        else:
            # defer setting timeout until we have a socket
            self._deferred_socket_actions.append(lambda s : s.settimeout(value))

    def setsockopt(self, level, optname, value):
        sock = None
        if self.type == SAM.SOCK_STREAM:
            sock = self._data_sock
        elif self.type == SAM.SOCK_DGRAM:
            sock = self._dgram_sock
        if sock:
            sock.setsockopt(level, optname, value)
        else:
            # defer setting, no socket yet
            self._deferred_socket_actions.append(lambda s : s.setsockopt(level, optname, value))

    def gettimeout(self):
        if self.type == SAM.SOCK_STREAM:
            return self._data_sock.gettimeout()
        elif self.type == SAM.SOCK_DGRAM:
            return self._dgram_sock.gettimeout()
        else:
            # TODO: implement this?
            return None
            
    def setblocking(self, flag):
        self._blocking_flag = flag
        sock = None
        if self.type == SAM.SOCK_STREAM:
            sock = self._data_sock
        elif self.type == SAM.SOCK_DGRAM:
            sock = self._dgram_sock
        if sock:
            sock.setblocking(flag)
        elif flag is not None:
            # if we have no socket yet, add this to be executed later
            self._deferred_socket_actions.append(lambda s : s.setblocking(flag))

    def makefile(self, *args, **kwargs):
        if self.type == SAM.SOCK_STREAM and self._data_sock:
            return self._data_sock.makefile(*args, **kwargs)
        else:
            # TODO: exception?
            return None
        
def lookup(name, samAddr=_defaultSAMAddr):
    """
    lookup an i2p name
    :returns i2p.datatypes.Destination:
    """
    sock = pysocket.socket()
    if isinstance(name, datatypes.Destination):
        # if it's already a destination return it :p
        return name
    # create new socket for lookup
    sock = pysocket.socket()
    try:
        sock.connect(_samAddr)
        repl = _sam_cmd(sock, 'HELLO VERSION MIN=3.0 MAX=3.2')
        if repl.opts['RESULT'] != 'OK':
            # fail to handshake
            sock.close()
            raise pysocket.error(errno.EAGAIN, "cannot connect to i2p router")
    except pysocket.timeout as ex:
        raise ex
    except pysocket.error as ex:
        raise ex
    else:
        # do lookup
        repl = _sam_cmd(sock, "NAMING LOOKUP NAME={}".format(name))
        # close socket as it is not needed anymore
        sock.close()
        if 'VALUE' in repl.opts:
            dest = datatypes.Destination(raw=repl.opts['VALUE'], b64=True)
            return dest
        else:
            # failed to lookup
            raise pysocket.herror(errno.EAGAIN, "name not resolved: {}".format(name))
