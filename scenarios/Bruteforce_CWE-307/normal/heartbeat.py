import time
import re
import select
import socket
import struct
import ssl
import sys
import os
import binascii
import random
import codecs


# ---------- HEARTBEAT USER SIMULATION ----------
# Possibility to creat valid heartbeat messages and send them to the server

class Heartbeat:

    def __init__(self, victim_ip, port, verbose):
        self._host = victim_ip
        self._port = port
        self._verbose = verbose

    def h2bin(self, x):
        return codecs.decode(x.replace(' ', '').replace('\n', ''), 'hex')

    def int2hex(self, x):
        hex_string = str.join("", ("%02x" % (x)))
        if len(hex_string) == 3:
            hex_string = '0' + hex_string
        elif len(hex_string) == 2:
            hex_string = '00' + hex_string
        elif len(hex_string) == 1:
            hex_string = '000' + hex_string
            return hex_string
        return hex_string

    def create_hello(self):
        return self.h2bin('''
        16 03 02 00  dc 01 00 00 d8 03 02 53
        43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
        bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
        00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
        00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
        c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
        c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
        c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
        c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
        00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
        03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
        00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
        00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
        00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
        00 0f 00 01 01
        ''')

    def create_hb(self):
        #TLS Heartbeat Message
        message_type = '01'
        payload_length = random.randint(4073, 2**14-1 - 19)
        payload = binascii.b2a_hex(os.urandom(payload_length)).decode()
        padding = binascii.b2a_hex(os.urandom(16)).decode()

        #TLS Record
        content_type = '18'
        tls_version = '03 02'
        length = self.int2hex(payload_length + 19)

        return self.h2bin(content_type + tls_version + length + message_type + self.int2hex(payload_length) + payload + padding)

    def recvall(self, sock, count):
        buf = b''
        while count:
            newbuf = sock.recv(count)
            if not newbuf: return None
            buf += newbuf
            count -= len(newbuf)
            return buf

    def hit_hb(self, s):
        # send heartbeat request to the server
        s.send(self.create_hb())
        
        #start listening the answer from the server
        while True:

            # first get the 5 bytes of the request : content_type, version, length
            hdr = s.recv(5)
            if hdr is None:
                print ('Unexpected EOF receiving record header - server closed connection')
                return False
            (content_type, version, length) = struct.unpack('>BHH', hdr)
            
            if content_type is None:
                print ('No heartbeat response received, server likely not vulnerable')
                return False
            
            # we can't use s.recv(length) because the server can separate the packet heartbeat into different smaller packet
            pay = self.recvall(s,length)
            if pay is None:
                print ('Unexpected EOF receiving record payload - server closed connection')
                return False
            
            if self._verbose:
                sys.stdout.write(' ... received message: type = %d, ver = %04x, length = ' % (content_type, version))
                if content_type == 24 and len(pay) > 3:
                    sys.stdout.write(str(len(pay)))
                else:
                    sys.stdout.write(str(len(pay)))
                    print ('')

            # heartbeat content type is 24 check rfc6520
            if content_type == 24:
                if self._verbose:
                    print ('\n')
                    print ('Received heartbeat response \n')
                return True

            # error
            if content_type == 21:
                print ('Received alert:')
                print ('Server returned error')
                return False

    def do_heartbeat(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self._verbose:
            print ('Connecting...')
        s.connect((self._host, self._port))

        if self._verbose:
            print ('Sending Client Hello...')
        s.send(self.create_hello())
        # pass the handshake
        while True:
            hdr = s.recv(5)
            (content_type, version, length) = struct.unpack('>BHH', hdr)
            hand = self.recvall(s,length)
            if self._verbose:
                print(' ... received message: type = %d, ver = %04x, length = %d' % (content_type, version, len(hand)))
            # Look for server hello done message.
            if content_type == 22:
                break

        if self._verbose:
            print ('Handshake done...')
            print ('Sending heartbeat request with length ' + '4' + ' :')
        self.hit_hb(s)

