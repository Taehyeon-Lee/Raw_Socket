#!/usr/bin/env python3

import random
import socket
import struct


class TCP_layer:
    '''
    Initializes a TCP Layer object that is capable of creating and managing TCP layer packets

    PARAMETERS:
        - src_IP: the source IP address of the packet
        - src_port: the source port being used
        - dst_ip: the destination IP address of where the packet is going
        - dst_port: the destination port being used
        - payload: the payload being sent

    RETURNS:
        - None
    '''
    def __init__(self, src_IP, src_port, dst_IP, dst_port, payload):
        self.src_IP = src_IP
        self.src_port = src_port
        self.dst_IP = dst_IP
        self.dst_port = dst_port
        self.payload = payload
        self.seq_num = random.randint(0, 100000)
        self.ack_num = 0
        self.offset = 5
        self.fin_flag = 0
        self.syn_flag = 0
        self.rst_flag = 0
        self.psh_flag = 0
        self.ack_flag = 0
        self.urg_flag = 0
        self.flags = None
        self.window = socket.htons(30845)	# match server behavior (observed in wireshark)
        self.checksum = 0
        self.urg_ptr = 0
        self.temp_header = None
        self.pseudo_packet = None
        self.final_header = None

        # convert and set payload
        if len(self.payload) > 0:
            self.payload_to_byte()
        else:
            self.payload = b""

    '''
    Encodes a TCP packet's payload to a byte string

    PARAMETERS:
        - None

    RETURNS:
        - None
    '''
    def payload_to_byte(self):
        if type(self.payload) is str:
            self.payload = self.payload.encode('utf-8')

    '''
    Sets all flag values for a packet to the encoded version

    PARAMETERS:
        - None

    RETURNS:
        - None
    '''
    def set_all_flags(self):
        self.flags = self.fin_flag + (self.syn_flag << 1) + (self.rst_flag << 2) + (self.psh_flag << 3) + \
                     (self.ack_flag << 4) + (self.urg_flag << 5)

    '''
    Creates a temporary header so the checksum value can be calculated

    PARAMETERS:
        - None

    RETURNS:
        - None
    '''
    def create_temp_header(self):
        self.temp_header = struct.pack('!HHLLBBH', self.src_port, self.dst_port, self.seq_num, self.ack_num, (
                self.offset << 4), self.flags, self.window) + struct.pack('H', self.checksum) \
                + struct.pack('!H', self.urg_ptr)

    '''
    Creates a pseudo packet so the checksum value can be calculated using the temporary header

    PARAMETERS:
        - None

    RETURNS:
        - None
    '''
    def create_pesudo(self):
        tcp_length = len(self.payload) + (self.offset * 4)
        self.pseudo_packet = struct.pack('!4s4sBBH', socket.inet_aton(self.src_IP), socket.inet_aton(self.dst_IP), 0,
                                         socket.IPPROTO_TCP, tcp_length)

    '''
        Combines pseudo, temp, and payload to be one full TCP packet

        PARAMETERS:
            - None

        RETURNS:
            - TCP packet with payload
        '''
    def combine_packets_to_calculate_checksum(self):
        return self.pseudo_packet + self.temp_header + self.payload

    """
    Calculates and sets checksum values for tcp packets

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

        self.checksum = Csum

    """
    Inserts the calculated checksum into the packet data and packs all values to create a finalized, sendable TCP packet

    PARAMETERS:
        - None

    RETURNS:
        - None
    """
    def finalize_packet(self):
        self.final_header = struct.pack('!HHLLBBH', self.src_port, self.dst_port, self.seq_num, self.ack_num, (
                self.offset << 4), self.flags, self.window)
        self.final_header += struct.pack('H', self.checksum)
        self.final_header += struct.pack('!H', self.urg_ptr)
        self.final_header += self.payload
