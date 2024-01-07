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

# to represent an outgoing TCP packet


class OutgoingPacket():
    # initialize object
    def __init__(self, sock, data=""):
        self.sock = sock
        self.data = data

        self.src_ip = sock.src_ip
        self.dst_ip = sock.dst_ip
        self.src_port = sock.src_port
        self.dst_port = sock.dst_port

        # dummy values which will be changed to 1 depending on whether the packet being sent is a SYN, FIN, or ACK
        self.syn = 0
        self.ack = 0
        self.fin = 0
        self.psh = 0

    # create relevant IP header
    def create_ip_header(self, src_ip, dest_ip):
        source_ip = self.src_ip
        dest_ip = self.dest_ip

        # ip header fields
        ip_ihl = 5  # internet header length
        ip_ver = 4  # version
        ip_tos = 0  # type of service
        ip_total_len = 0  # kernel will fill the correct total length
        ip_id = 54321  # id of this packet
        ip_flag_offset = 0
        ip_ttl = 255  # packet lifetime, or time-to-live
        ip_protocol = socket.IPPROTO_TCP
        ip_checksum = 0  # kernel will fill the correct checksum

        ip_src_addr = socket.inet_aton(source_ip)
        ip_dest_addr = socket.inet_aton(dest_ip)

        ip_ihl_ver = (ip_ver << 4) + ip_ihl

        # the ! in the pack format string means network order
        ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_total_len,
                         ip_id, ip_flag_offset, ip_ttl, ip_protocol, ip_checksum, ip_src_addr, ip_dest_addr)

        return ip_header

    # create relevant TCP header
    def create_tcp_header(self):
        # tcp header fields
        tcp_source = self.src_port
        tcp_dest = self.dest_port
        tcp_seq = 454
        tcp_ack_seq = 0
        tcp_doff = 5  # offset; size of tcp header = 5 * 4 = 20 bytes

        # tcp flags
        tcp_fin = self.fin
        tcp_syn = self.syn
        tcp_psh = self.psh
        tcp_ack = self.ack
        tcp_rst = 0
        tcp_urg = 0
        tcp_window = socket.htons(5840)  # maximum allowed window size
        tcp_check = 0
        tcp_urg_ptr = 0

        tcp_offset_res = (tcp_doff << 4) + 0
        tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + \
            (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)

        # the ! in the pack format string means network order
        tcp_header = pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq,
                          tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

        # pseudo header fields
        source_address = socket.inet_aton(tcp_source)
        dest_address = socket.inet_aton(tcp_dest)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header) + len(self.data)

        psh = pack('!4s4sBBH', source_address, dest_address,
                   placeholder, protocol, tcp_length)

        psh = psh + tcp_header + self.data

        tcp_check = self.checksum(psh)

        # make the tcp header again with the correct checksum
        tcp_header = pack('!HHLLBBH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res,
                          tcp_flags,  tcp_window) + pack('H', tcp_check) + pack('!H', tcp_urg_ptr)

        return tcp_header

    # verify checksum for TCP header
    def checksum(self, msg):
        s = 0

        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            w = ord(msg[i]) + (ord(msg[i + 1]) << 8)
            s = s + w

        s = (s >> 16) + (s & 0xffff)
        s = s + (s >> 16)

        # complement and mask to 4 byte short
        s = ~s & 0xffff

        return s

    # create complete packet using relevant IP header, TCP header, and web data
    def create_packet(self):
        ip_header = self.create_ip_header(self.src_ip, self.dest_ip)
        tcp_header = self.create_tcp_header(self.src_port, self.dest_port)

        # compiling into final packet and returning
        packet = ip_header + tcp_header + self.data

        return packet
