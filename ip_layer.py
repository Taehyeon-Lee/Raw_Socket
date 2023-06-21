#!/usr/bin/env python3

import socket
import struct
import random

class IP_layer:
    """
    Initialized an IP Layer object that is capable of creating and managing IP layer packet

    PARAMETERS:
        - src_ip: the source IP address of the packet
        -  dst_ip: the destination IP address of the packet where it is delivered to
    """
    def __init__(self, src_ip, dst_ip):
        self.header = None
        self.create_ipv4_fields()
        self.ip_src_addr = src_ip
        self.ip_dst_addr = dst_ip

    """
    Creates the header fields of ip layer with IPv4 version and sets the fields values

    PARAMETERS:
        - None
        
    RETURNS:
        - None
    """
    def create_ipv4_fields(self):
        ip_ver = 4  # version
        ip_ihl = 5  # header length
        self.ip_ihl = ip_ihl
        self.ip_ver = (ip_ver << 4) + ip_ihl

        # ---- [type of service]
        self.ip_tos = 0

        # ---- [ Total Length]
        self.ip_total_len = 0

        # ---- [ Identification ]
        self.ip_id = random.randint(0, 65535)

        # ---- [ Flags ]
        ip_flags = 2
        self.ip_frag_offset = 0
        self.ip_flg = (ip_flags << 13)

        # ---- [ Time to live]
        self.ip_ttl = 64

        # ---- [ Protocol ]
        self.ip_proto = socket.IPPROTO_TCP

        # ---- [ Check Sum ]
        self.ip_chk = 0

        # SRC and DST IP address is already set

    """
    Gather all fields of IP layer header and packs them as one IP header

    PARAMETERS:
        - None

    RETURNS:
        - None
    """
    def assemble_ip_packet(self):
        src_ip_byte = socket.inet_aton(self.ip_src_addr)
        dst_ip_byte = socket.inet_aton(self.ip_dst_addr)
        self.header = struct.pack('!BBHHHBBH4s4s',
                                  self.ip_ver,
                                  self.ip_tos,
                                  self.ip_total_len,
                                  self.ip_id,
                                  self.ip_flg + self.ip_frag_offset,
                                  self.ip_ttl,
                                  self.ip_proto,
                                  self.ip_chk,
                                  src_ip_byte,
                                  dst_ip_byte)
        return self.header

    """
    Sets ip total length field of the ip header

    PARAMETERS:
        - tcp_packet: TCP packet with data

    RETURNS:
        - None
    """
    def set_ip_total_len(self, tcp_packet):
        total_len = self.ip_ihl * 4 + len(tcp_packet)
        self.ip_total_len = total_len

    """
    Calculates and sets checksum values for ip packets

    PARAMETERS:
        - data: the specified piece of data to calculate a checksum for

    RETURNS:
        - None
    """
    def calculate_checksum(self, msg):
        Csum = 0

        for i in range(0, len(msg), 2):
            if (i + 1) < len(msg):
                a = msg[i]
                b = msg[i + 1]
                Csum = Csum + (a + (b << 8))
            elif (i + 1) == len(msg):
                Csum += msg[i]
            else:
                raise "Something Wrong here"

            # One's Complement
        Csum = Csum + (Csum >> 16)
        Csum = ~Csum & 0xffff

        self.ip_chk = Csum

    """
    validate checksum values for incoming packet of ip layer

    PARAMETERS:
    	- data: the specified piece of data to validate a checksum for

    RETURNS:
    	- Checksum value
    """
    def validate_checksum(self, data):
        # If the data length is odd, add a zero byte at the end
        if len(data) % 2 == 1:
            data += b'\x00'

        # Calculate the sum of 16-bit words
        words = struct.unpack('!%dH' % (len(data) // 2), data)
        sum_ = sum(words)

        # Calculate the one's complement sum
        sum_ = (sum_ >> 16) + (sum_ & 0xffff)
        sum_ = sum_ + (sum_ >> 16)

        # Return the one's complement of the sum
        return (~sum_) & 0xffff


    """
    Getter function that gets an IP header

    PARAMETERS:
        - None

    RETURNS:
        - IP header
    """
    def get_packet(self):
        return self.header
