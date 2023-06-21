#!/usr/bin/env python3

class Buffer_Item:
    '''
    Initializes an item that is held by the buffer

    PARAMETERS:
    	- ack_num: the acknowledgement number of the packet
    	- seq_num: the sequence number of the packet
    	- payload: the payload of the packet
    	- raw_packet: the raw value of the packet (encoded)
    	- src_addr: the IP address of the sender (server)

    RETURNS:
    	- None
    '''
    def __init__(self, ack_num, seq_num, payload, raw_packet, src_addr):
        self.ack_num = ack_num
        self.seq_num = seq_num
        self.payload = payload
        self.length = len(payload)
        self.raw_packet = raw_packet
        self.src_addr = src_addr
