#!/usr/bin/env python3

import socket
import sys
import struct
import random
import ip_only


'''
Finds the client IP address and port

PARAMETERS:
	- None

RETURNS:
	- The client IP address and port
'''
def get_client_ip_and_port():
	# create temp socket
	temp = socket.socket()
	temp.connect(("www.google.com", 80))

	# init IPs and ports
	client_ip, client_port = temp.getsockname()

	# close temp socket and return
	temp.close()
	return client_ip, client_port


'''
Creates a SOCK_RAW/IPPROTO_TCP socket for sending packets

PARAMETERS:
	- client_ip: the client IP address
	- client_port: the client port
	- server_ip: the server IP address
	- server_port: the server port

RETURNS:
	- The created SOCK_RAW/IPPROTO_TCP socket
'''
def create_IPPROTO_TCP_send(client_ip, client_port, server_ip, server_port):
	try:
		# create raw socket
		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

		# set the source IP and port
		s.bind((client_ip, client_port))

		# Set the IP header to be included in the raw packet
		s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

		# connect
		s.connect((server_ip, server_port))

		return s
	except socket.error as msg:
		print('Socket (send) could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
		sys.exit()


'''
Creates a SOCK_RAW/IPPROTO_RAW socket for receiving packets

PARAMETERS:
	- client_ip: the client IP address

RETURNS:
	- The created SOCK_RAW/IPPROTO_RAW socket
'''
def create_IPPROTO_RAW_receive(client_ip):
	try:
		# create raw socket
		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

		# Indicate that we'll be constructing our own IP header
		# Uncomment once IP layer is finished ************************************************
		s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

		# bind receive socket to local address and random port
		s.bind((client_ip, 0))

		return s
	except socket.error as msg:
		print(msg)
		print('Socket (receive) could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
		sys.exit()


"""
Establishes TCP connection with 3-way handshake protocol

PARAMETERS:
	- send_sock: the socket created for sending from client to server
	- recv_sock: the socket created for receiving from server to client
	- client_ip: the client IP address
	- client_port: the client port
	- server_ip: the server IP address
	- server_port: the server port

RETURNS:
	- True if TCP session was successfully established, False otherwise
"""
def three_way_handshake(send_sock, recv_sock, client_ip, client_port, server_ip, server_port):
	# C-->S SYN
	status, attempts = send_SYN(send_sock, client_ip, client_port, server_ip, server_port, 1)

	# S-->C SYN ACK
	client_ip_SYNACK, client_port_SYNACK, server_ip_SYNACK, server_port_SYNACK, syn_flag_SYNACK, \
		ack_flag_SYNACK, psh_flag_SYNACK, fin_flag_SYNACK, count_SYNACK, seq_num_s, ack_num_s = \
		receive_packet(recv_sock, server_ip, server_port)


	# # C-->S ACK
	ack_packet, seq_num, ack_num = complete_handshake(client_ip_SYNACK, client_port_SYNACK, server_ip_SYNACK, server_port_SYNACK,
									ack_flag_SYNACK, seq_num_s, ack_num_s)
	status, attempts = send_TWH_ACK(send_sock, client_ip, client_port, server_ip, server_port, 1, ack_packet)

	return status, seq_num, ack_num


"""
Sends a SYN packet to the server for step 1 of the 3-way handshake protocol

PARAMETERS:
	- sock: the socket created for sending from client to server
	- client_ip: the client IP address
	- client_port: the client port
	- server_ip: the server IP address
	- server_port: the server port
	- attempts: the number of attempts it takes to send the SYN (initially set at 1)

RETURNS:
	- True if SYN packet was successfully sent, False otherwise
	- The number of attempts it took so successfully send the SYN
"""
def send_SYN(sock, client_ip, client_port, server_ip, server_port, attempts):
	if (attempts > 10):
		# Too many attempts to find an open port - "timeout"
		return False

	try:
		# construct ip header and tcp header for syn
		ip_header = ip_only.IP_layer()
		tcp_header = create_syn_packet(client_ip, client_port, server_ip, server_port)

		# calculate ip total len and reset it
		ip_tot_len = ip_header.ip_ihl * 4 + len(tcp_header)
		ip_header.recalculate_ip_tot_len(ip_tot_len)

		# assemble packet and send
		ip_header.assemble_ip_packet()
		ip_header.send_packet(sock, tcp_header)

		return True, attempts

		# syn_packet = create_syn_packet(client_ip, client_port, server_ip, server_port)
		# sock.sendto(syn_packet, (server_ip, server_port))

	except socket.error:
		print(f"Port {client_port} is in use.")
		client_port = random.randint(1024, 65535)
		print(f"Trying again with port {client_port}...")
		attempts += 1
		send_SYN(sock, client_ip, client_port, server_ip, server_port, attempts)


"""
Creates a SYN packet

PARAMETERS:
	- client_ip: the client IP address
	- client_port: the client port
	- server_ip: the server IP address
	- server_port: the server port

RETURNS:
	- The created SYN packet
"""
def create_syn_packet(client_ip, client_port, server_ip, server_port):
	# tcp header
	seq_num = random.randint(0, 100000)
	ack_num = 0
	offset = 10	# 5 + 5 options change back to 10 later

	# tcp flags
	fin_flag = 0
	syn_flag = 1
	rst_flag = 0
	psh_flag = 0
	ack_flag = 0
	urg_flag = 0

	flags = fin_flag + (syn_flag << 1) + (rst_flag << 2) + (psh_flag <<3) + (ack_flag << 4) + (urg_flag << 5)

	window = socket.htons(61690)	# match server behavior (observed in wireshark)
	checksum = 0
	urg_ptr = 0

	# Construct TCP options
	mss = struct.pack('!BBH', 2, 4, 1460)  # Maximum Segment Size: 1460 bytes
	sack_perm = struct.pack('!BB', 4, 2)  # SACK Permitted
	ts = struct.pack('!BBLL', 8, 10, 0, 0)  # Timestamps
	nop = struct.pack('!B', 1)  # No-Operation
	wscale = struct.pack('!BBB', 3, 3, 7)  # Window Scale: 7 (multiply by 128)

	# build the TCP header with options
	tcp_options = mss + sack_perm + ts + nop + wscale

	tcp_header = struct.pack('!HHLLBBHHH', client_port, server_port, seq_num, ack_num, (offset << 4), flags, window,
							 checksum, urg_ptr)  + tcp_options

	# calculate checksum
	tcp_pseudo = struct.pack('!4s4sBBH', socket.inet_aton(client_ip), socket.inet_aton(server_ip), 0, socket.IPPROTO_TCP,
							 len(tcp_header))
	tcp_pseudo += tcp_header

	checksum = calculate_checksum(tcp_pseudo)

	# update tcp_header with the calculated checksum
	tcp_header = struct.pack('!HHLLBBH', client_port, server_port, seq_num, ack_num, (offset << 4), flags,
					  window) + struct.pack('H', checksum) + struct.pack('!H', urg_ptr) + tcp_options

	# construct and return the packet
	return tcp_header


"""
Calculates checksum values

PARAMETERS:
	- data: the specified piece of data to calculate a checksum for

RETURNS:
	- The calculated checksum value
"""
def calculate_checksum(data):
	cSum = 0
	for i in range(0, len(data) - 1, 2):
		w = data[i] + (data[i + 1] << 8)
		cSum = cSum + w

	cSum = (cSum >> 16) + (cSum & 0xffff)
	cSum = cSum + (cSum >> 16)

	cSum = ~cSum & 0xffff  # complement and mask to 4 byte short

	return cSum

def validate_checksum(ip_header):

	iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
	checksum = iph[7]

	# calculate the checksum
	# set the checksum field to zero before calculating the checksum
	iph = iph[:7] + (0,) + iph[8:]
	s = 0
	for i in range(0, len(iph), 2):
		w = (iph[i] << 8) + iph[i + 1]
		s += w
	s = (s >> 16) + (s & 0xffff)
	s = ~s & 0xffff

	# compare the calculated checksum with the extracted checksum
	if checksum == s:
		print('Packet is valid')
	else:
		print('Packet is corrupted')


"""
Receives a packet from the server

PARAMETERS:
	- recv_sock: the socket created for receiving from server to client
	- server_ip: the server IP address
	- server_port: the server port

RETURNS:
	- s_addr: the IP address of the sender (server)
	- source_port: the port used by the sender (server)
	- d_addr: the IP address of the receiver (client)
	- dest_port: the port used by the receiver (client)
	- syn_flag: indicates whether or not the packet is a SYN packet
	- ack_flag: indicates whether or not the packet is a ACK packet
	- psh_flag: indicates whether or not the packet is a PSH packet
	- fin_flag: indicates whether or not the packet is a FIN packet
	- count: the number of packets checked before finding the SYN/ACK packet
	- sequence: the sequence number of the packet
	- ack_seq: the ack number of the packet
"""
def receive_packet(recv_sock, server_ip, server_port):
	count = 1
	while True:
		# Receive packet data
		packet_data, _ = recv_sock.recvfrom(4096)
		s_addr = _[0]

		# continue only if server IP matches
		if s_addr == server_ip:
			# Unpack the IP header
			ip_header = packet_data[0:20]
			iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
			version_ihl = iph[0]
			version = version_ihl >> 4
			ihl = version_ihl & 0xF
			iph_length = ihl * 4
			ttl = iph[5]
			protocol = iph[6]
			d_addr = socket.inet_ntoa(iph[9])  # original client ip add

			###### validate checksum #########
			print("ip matched and now validate checksum")
			chksum_field = iph[7]
			iph = iph[:7] + (0,) + iph[8:]
			s = 0
			for i in range(0, len(iph), 2):
				w = (iph[i] << 8) + iph[i + 1]
				s += w
			s = (s >> 16) + (s & 0xffff)
			s = ~s & 0xffff

			# compare the calculated checksum with the extracted checksum
			if chksum_field == s:
				print('Packet is valid')
			else:
				print('Packet is corrupted')


			# Unpack the TCP header
			tcp_header = packet_data[iph_length:iph_length + 20]
			tcph = struct.unpack('!HHLLBBHHH', tcp_header)
			source_port = tcph[0]  # server port 80

			if source_port == server_port:
				dest_port = tcph[1] # client port
				sequence = tcph[2]
				ack_seq = tcph[3]
				doff_reserved = tcph[4]
				tcph_length = doff_reserved >> 4
				syn_flag = (tcph[5] & 0x02) != 0
				ack_flag = (tcph[5] & 0x10) != 0
				psh_flag = (tcph[5] & 0b00001000) != 0
				fin_flag = (tcph[5] & 0b00000001) != 0

				payload = packet_data[iph_length + tcph_length + 15:]
				# try:
				# 	print(payload)
				# 	payload = payload.decode("utf-8")
				# 	print(payload)
				# except:
				# 	print("passing")
				# 	pass

				return s_addr, source_port, d_addr, dest_port, syn_flag, ack_flag, psh_flag, fin_flag, count, sequence,\
						ack_seq

		# received a packet not intended for us - continue
		count += 1
		continue


"""
Create a ACK packet to send to server for step 3 of the 3-way handshake protocol

PARAMETERS:
	- server_ip: the server IP address
	- server_port: the server port
	- client_ip: the client IP address
	- client_port: the client port
	- ack_flag: ack flag received from SYN/ACK packet from the server
	- seq_num_P: sequence number from SYN/ACK packet
	- ack_num_P: ACK number from SYN/ACK packet

RETURNS:
	- tcp_header: the constructed tcp header
	- seq_num: sequence number of the packet
	- ack_num: ACK number of the packet
"""
def complete_handshake(server_ip, server_port, client_ip, client_port, ack_flag, seq_num_P, ack_num_P):
	# tcp header
	offset = 5  # 5 because w/o option

	# set sequence number and ack number
	seq_num = ack_num_P
	ack_num = seq_num_P + 1

	# tcp flags
	fin_flag = 0
	syn_flag = 0
	rst_flag = 0
	psh_flag = 0
	urg_flag = 0

	# ack_flag is reused from unpack packet and set the flag
	flags = fin_flag + (syn_flag << 1) + (rst_flag << 2) + (psh_flag << 3) + (ack_flag << 4) + (urg_flag << 5)

	# window = socket.htons(5840)
	window = socket.htons(61690)  # match server behavior (observed in wireshark)
	checksum = 0
	urg_ptr = 0

	tcp_header = struct.pack('!HHLLBBHHH', client_port, server_port, seq_num, ack_num, (offset << 4), flags, window,
							 checksum, urg_ptr)
	# calculate checksum
	tcp_pseudo = struct.pack('!4s4sBBH', socket.inet_aton(client_ip), socket.inet_aton(server_ip), 0, socket.IPPROTO_TCP,
							 len(tcp_header))
	tcp_pseudo += tcp_header

	checksum = calculate_checksum(tcp_pseudo)

	# update tcp_header with the calculated checksum
	tcp_header = struct.pack('!HHLLBBH', client_port, server_port, seq_num, ack_num, (offset << 4), flags,
							 window) + struct.pack('H', checksum) + struct.pack('!H', urg_ptr)

	# construct and return the packet
	return tcp_header, seq_num, ack_num

"""
Sends a ACK packet to the server for step 3 of the 3-way handshake protocol

PARAMETERS:
	- sock: the socket created for sending from client to server
	- client_ip: the client IP address
	- client_port: the client port
	- server_ip: the server IP address
	- server_port: the server port
	- attempt: count attempts
	- ack_packet: TCP header that needs to be included for ACK packet

RETURNS:
	- True if ACK packet was successfully sent, False otherwise
"""
def send_TWH_ACK(sock, client_ip, client_port, server_ip, server_port, attempts, ack_packet):
	if (attempts > 10):
		# Too many attempts to find an open port - "timeout"
		return False

	try:
		# construct ip header and tcp header for syn
		ip_header = ip_only.IP_layer()
		tcp_header = ack_packet

		# calculate ip total len and reset it
		ip_tot_len = ip_header.ip_ihl * 4 + len(tcp_header)
		ip_header.recalculate_ip_tot_len(ip_tot_len)

		# assemble packet and send
		ip_header.assemble_ip_packet()
		ip_header.send_packet(sock, tcp_header)

		return True, attempts
	except socket.error:
		print(f"Port {client_port} is in use.")
		client_port = random.randint(1024, 65535)
		print(f"Trying again with port {client_port}...")
		attempts += 1
		send_TWH_ACK(sock, client_ip, client_port, server_ip, server_port, attempts, ack_packet)

def request_GET_http(send_sock, recv_sock, client_ip, client_port, server_ip, server_port, seq_num_init, ack_num_init):
	# C-->S GET HTTP (layered on top of a TCP) request
	# create packet and send it to server
	http_packet = create_http_packet(server_ip, server_port, client_ip, client_port, seq_num_init, ack_num_init)
	send_http_req(send_sock, http_packet, client_ip, client_port, server_ip, server_port, 1)

	# receive 2 ACKs back from server; 1 for HTTP GET request and 1 that begins sending data
	s_addr, source_port, d_addr, dest_port, syn_flag, ack_flag, psh_flag, fin_flag, count, sequence, ack_seq = \
		receive_packet(recv_sock, server_ip, server_port)

	s_addr, source_port, d_addr, dest_port, syn_flag, ack_flag, psh_flag, fin_flag, count, sequence, ack_seq = \
		receive_packet(recv_sock, server_ip, server_port)

	# validate the ACKs and send the one with data to the receive_payload function


"""
Creates a packet with http request

PARAMETERS:
	- client_ip: the client IP address
	- client_port: the client port
	- server_ip: the server IP address
	- server_port: the server port
	- seq_num: seq number used for ack packet
	- ack_num: ack number used for ack paket

RETURNS:
	- The created a packet with ip header, tcp header, and http get req
"""
def create_http_packet(server_ip, server_port, client_ip, client_port, seq_num, ack_num):
	##### http request #####
	# req = b"GET / HTTP/1.1\r\nHost: david.choffnes.com\r\n\r\n"
	req = b"GET /classes/cs5700f22/10MB.log HTTP/1.1\r\nHost: david.choffnes.com\r\n\r\n"

	###### tcp header ######
	offset = 5  # 5 because w/o option

	# tcp flags
	fin_flag = 0
	syn_flag = 0
	rst_flag = 0
	psh_flag = 1
	ack_flag = 1
	urg_flag = 0

	# ack_flag is reused from unpack packet and set the flag
	flags = fin_flag + (syn_flag << 1) + (rst_flag << 2) + (psh_flag << 3) + (ack_flag << 4) + (urg_flag << 5)

	window = socket.htons(61690)  # match server behavior (observed in wireshark)
	checksum = 0
	urg_ptr = 0

	tcp_header = struct.pack('!HHLLBBHHH', client_port, server_port, seq_num, ack_num, (offset << 4), flags, window,
							 checksum, urg_ptr)
	# calculate checksum
	tcp_pseudo = struct.pack('!4s4sBBH', socket.inet_aton(client_ip), socket.inet_aton(server_ip), 0,
							 socket.IPPROTO_TCP, len(tcp_header) + len(req))
	tcp_pseudo += tcp_header + req

	checksum = calculate_checksum(tcp_pseudo)

	# update tcp_header with the calculated checksum
	tcp_header = struct.pack('!HHLLBBH', client_port, server_port, seq_num, ack_num, (offset << 4), flags,
							 window) + struct.pack('H', checksum) + struct.pack('!H', urg_ptr) + req

	##### IP header #####

	# construct ip header and tcp header for syn
	ip_header = ip_only.IP_layer()

	# calculate ip total len and reset it
	ip_tot_len = ip_header.ip_ihl * 4 + len(tcp_header) + len(req)
	ip_header.recalculate_ip_tot_len(ip_tot_len)

	# assemble ip header and construct packet
	ip_header.assemble_ip_packet()
	packet = ip_header.packet + tcp_header

	# calculate checksum
	checksum_ip_lv = ip_header.checksum(packet)
	ip_header.set_checksum(checksum_ip_lv)

	# assemble ip header construct final packet and return
	ip_header.assemble_ip_packet()
	packet = ip_header.packet + tcp_header
	return packet

"""
Sends a packet with http req to the server

PARAMETERS:
	- sock: the socket created for sending from client to server
	- client_ip: the client IP address
	- client_port: the client port
	- server_ip: the server IP address
	- server_port: the server port
	- attempt: count attempts
	- packet: packet includes both ip and tcp header with http req

RETURNS:
	- True if the packet was successfully sent, False otherwise
"""
def send_http_req(sock, packet, client_ip, client_port, server_ip, server_port, attempts):
	if (attempts > 10):
		# Too many attempts to find an open port - "timeout"
		return False

	try:
	# if want to create ip header and send through ip class use this and change ip_header.packet to ip_header above func
		# # construct ip header and tcp header for syn
		# ip_header = ip_only.IP_layer()
		#
		# # calculate ip total len and reset it
		# ip_tot_len = ip_header.ip_ihl * 4 + len(packet)
		# ip_header.recalculate_ip_tot_len(ip_tot_len)
		#
		# # assemble packet and send
		# ip_header.assemble_ip_packet()
		# ip_header.send_packet(sock, packet)
		sock.sendto(packet, (server_ip, server_port))
		return True, attempts

	except socket.error:
		print(f"Port {client_port} is in use.")
		client_port = random.randint(1024, 65535)
		print(f"Trying again with port {client_port}...")
		attempts += 1
		send_http_req(sock, packet, client_ip, client_port, server_ip, server_port, attempts)


if __name__ == "__main__":
	# init IPs and ports
	client_ip, client_port = get_client_ip_and_port()
	server_ip = '204.44.192.60'
	server_port = 80

	# create raw sockets for sending and receiving
	send_sock = create_IPPROTO_TCP_send(client_ip, client_port, server_ip, server_port)
	recv_sock = create_IPPROTO_RAW_receive(client_ip)

	# 3 way handshake
		# C-->S SYN
		# S-->C SYN ACK
		# C-->S ACK
	status, seq_num, ack_num = three_way_handshake(send_sock, recv_sock, client_ip, client_port, server_ip, server_port)

	# communicate with server with http
	# request_GET_http(send_sock, recv_sock, client_ip, client_port, server_ip, server_port, seq_num,
	# 				 ack_num)

	send_sock.close()
	recv_sock.close()






	# C-->S GET HTTP (layered on top of a TCP) request

	# S-->C ACK of GET request

	# Data flow
		# while data
			# S-->C data transfer
			# C-->S ack

	# S-->C OK HTTP (layered on top of a TCP) message
	# C-->S ACK (for the HTTP OK message)

	# Termination
		# S-->C FIN ACK
		# C-->S FIN ACK
		# S-->C ACK