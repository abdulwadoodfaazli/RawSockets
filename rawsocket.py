#!/usr/bin/env python3

import sys
import time
import socket
import struct
from struct import *
import http
import urllib
from urllib.parse import urlparse
import incoming
import outgoing

# define some constants

HTTP_VERSION = "HTTP/1.0"
LINE_ENDING = "\r\n"  # CRLF


class RawSocket():
    # initialize object
    def __init__(self, url):
        # create two raw sockets
        try:
            # send socket
            self.sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            # receive socket
            self.rcv_sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except:
            print("Socket could not be created.")
            sys.exit()

        # get necessary address and port information for packet

        hostname = socket.gethostname()  # get hostname of local machine
        # get IP address of local machine based on its name
        self.src_ip = socket.gethostbyname(hostname)
        # get IP address of destination
        self.dest_ip = socket.gethostbyname(url)

        # get TCP ports for source and destination
        self.src_tcp = 65535  # randomly selecting the last available port
        self.dest_tcp = 80

    # connect to a given network by performing the 3-way handshake
    def connect_socket(self, url, port):
        self.dest_ip = socket.gethostbyname(url)
        self.dest_tcp = port
        self.send_syn()
        self.rcv_ack()
        self.send_ack()

    # send a synchronize packet to the network
    def send_syn(self):
        # since we will be 'sending' a SYN, it will be an instance of OutgoingPacket()
        # note that since our OutgoingPacket() takes in 2 parameters (sock and data), we need to send them too. However, data is optional, with the value "" being used when it is not provided. So we only need to provide the socket at least, which is this class itself, so we just use 'self' as the argument here
        packet = outgoing.OutgoingPacket(self)
        # since we will be sending a SYN, we make it's 'syn' attribute 1
        packet.syn = 1
        # send the packet to the destination ip address at port 0
        self.socket.sendto(packet.create_packet(), (self.dest_ip, 0))

    # send an acknowledgement packet to network
    def send_ack(self):
        # since we will be sending an ACK, it will be an instance of OutgoingPacket()
        packet = outgoing.OutgoingPacket(self)
        # since we will be sending an ACK, we make it's 'ack' attribute 1
        packet.ack = 1
        # send the packet to the destination ip address at port 0
        self.socket.sendto(packet.create_packet(), (self.dest_ip, 0))

    # send a fin packet to close a connection with the network
    def send_fin(self):
        # since we will be sending a FIN, it will be an instance of OutgoingPacket()
        packet = outgoing.OutgoingPacket(self)
        # since we will be sending a FIN, we make it's 'ack' and 'fin' attributes 1
        packet.ack = 1
        packet.fin = 1
        # send the packet to the destination ip address at port 0
        self.socket.sendto(packet.create_packet(), (self.dest_ip, 0))

    # to send a complete packet (with data) to the network
    def send(self, data):
        packet = outgoing.OutgoingPacket(self, data)
        packet.ack = 1
        packet.psh = 1
        self.socket.sendto(packet.create_packet(), (self.dest_ip, 0))
        self.rcv_ack()

    # to ensure that the received packet is the intended one
    # we also need to make sure that the ack is received within 1 minute. Otherwise, we quit.
    def rcv_ack(self, bytes=65565):
        start_time = time.time()
        time.clock()
        seconds = 0

        while seconds < 60:
            seconds = time.time() - start_time
            packet = self.rcv_sock.recvfrom(65565)
            ip_address = packet[1][0]
            if ip_address == self.dest_ip:
                packet = incoming.IncomingPacket()
                parsed_packet = packet.parse()
                self.seq = parsed_packet.seq
                self.ack = parsed_packet.seq + parsed_packet.data_size + 1
                return packet
            
        raise Exception("Didn't receive packet in time...")


    # receive the body of the response and parses it as a string
    def rcv(self, bytes=65565):
        data = ""
        while True:
            packet = self.rcv_next()
            data += packet.data
            self.send_ack()
            if packet.flg_fin:
                return data

    # close a connection between our program and the network
    def close(self):
        self.send_fin()
        self.rcv_next()
        self.send_ack()
