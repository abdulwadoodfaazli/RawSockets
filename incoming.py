#!/usr/bin/env python3

import sys
import socket
import struct
from struct import *
import http
import urllib
from urllib.parse import urlparse

# define some constants

HTTP_VERSION = "HTTP/1.0"
LINE_ENDING = "\r\n"  # CRLF

# to represent an incoming TCP packet
class IncomingPacket():
    # initialize object
    def __init__(self, packet):
        # set everything as zero initially
        self.packet = packet[0]
        self.src_port = 0
        self.dst_port = 0
        self.seq = 0
        self.ack = 0
        self.offset = 0
        self.flags = 0
        self.flg_fin = 0
        self.flg_syn = 0
        self.flg_rst = 0
        self.flg_psh = 0
        self.flg_ack = 0
        self.flg_urg = 0
        self.window = 0
        self.checksum = 0
        self.urg_ptr = 0
        self.header_size = 0
        self.data_size = 0
        self.data = 0

    # parse an incoming TCP/IP packet
    def parse_incoming_packet(self, packet):
        # unpack the header to get individual attributes
        header = unpack('!HHLLBBHHH', packet[20:40])

        self.src_port = header[0]
        self.dst_port = header[1]
        self.seq = header[2]
        self.ack = header[3]
        self.offset = header[4]
        self.flags = header[5]
        self.window = header[6]
        self.checksum = header[7]
        self.urg_ptr = header[8]

        # calculate flag attributes
        self.flg_fin = (self.flags & 1)
        self.flg_syn = (self.flags & 2) >> 1
        self.flg_rst = (self.flags & 4) >> 2
        self.flg_psh = (self.flags & 8) >> 3
        self.flg_ack = (self.flags & 16) >> 4
        self.flg_urg = (self.flags & 32) >> 5

        self.header_size = 20 + (4 * (self.offset >> 4))
        self.data_size = len(self.packet) - self.header_size
        self.data = self.packet[self.header_size:]

        return self