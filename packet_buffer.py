#!/usr/bin/env python3

import buffer_item


class Packet_Buffer:
    '''
    Initializes a buffer for storing received packets

    PARAMETERS:
        - None

    RETURNS:
        - None
    '''
    def __init__(self):
        self.buffer = {}        # key: seq_num (int) | val: buffer_item (object)
        self.last_shipped_item = None
        self.last_received_item = None
        self.isn = 0            # initial seq num
        self.ian = 0            # initial ack num
        self.next_expected_ack = None
        self.next_expected_seq = None

    '''
    Removes an item from the buffer. Sets the item removed as the buffer's "last shipped item"

    PARAMETERS:
        - seq_num: the sequence number of the packet

    RETURNS:
        - None
    '''
    def remove(self, seq_num):
        last = self.buffer.pop(seq_num)
        self.last_shipped_item = last

    '''
    Reports if a packet exists in the buffer

    PARAMETERS:
        - seq_num: the sequence number of the packet that we are searching for

    RETURNS:
        - True if found in the buffer, false otherwise
    '''
    def search_for(self, seq_num):
        return seq_num in self.buffer
