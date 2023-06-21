CS5700 - SP2023
Project 4: Raw Sockets
Tae-Hyeon Lee + Mitchell Neides


High-level approach:

We began by researching in-depth the processes for creating and sending the IP and TCP layers for a raw socket.
This also involved writing a simple socket and an HTTP only program to download the example files, and observing
the behavior of the server in Wireshark.
Then, Tae-Hyeon took the lead for the IP layer and Mitchell took the lead for the TCP layer.
We both implemented separately each of the respective layers; Tae-Hyeon built the IP only layer and send UDP packets
to ensure that it worked, while Mitchell implemented the TCP only layer using a pseudo IP header to ensure that it
worked. Ted finished first, so he then helped complete the TCP only layer, and we then combined our implementations
and attempted to complete the 3-way handshake. Once this was completed, we continued on initiating the GET request
for the file, the exchange of data from the server followed by acknowledgements from the client, and finally the
teardown upon receipt of the FIN/ACK from the server. Once we completed the entire process, we then went back into our
program to implement the congestion window and timeout requirements.

High-level execution flow:
- init client IPs and ports
- parse command line to extract url, filename, server address, file location and hostname
- create raw sockets for sending and receiving
- initialize packet buffer
- 3 way handshake
		- C-->S SYN
		- S-->C SYN ACK
		- C-->S ACK
- C-->S GET HTTP request
- S-->C ACK GET HTTP
- while data
		- S-->C data transfer
		- C-->S ack
- break when FIN ACK received
- Termination
		- S-->C FIN ACK
		- C-->S FIN ACK
		- S-->C ACK
- close sockets and exit program


TCP/IP features implemented:
We implemented full IP and TCP functionality including 3-way handshake, IP and port validation, header creation and 
validation, header packing, checksum calculation, congestion window management, checksum validation, handling of 
duplicate packets, handling of out-of-order packets, timeouts, and teardown.


Challenges faced:

Probably the biggest challenge faced was figuring out how to correctly construct/pack the headers for our packets.
Wireshark shows the outer details of every packet sent, but the packed information in the headers is encoded, so it
is very difficult to debug incorrect formatting or other header packing errors.
We also got stuck for a while with our program acking incorrect values. It took us a long time, but eventually we
realized that the server was sending us larger packets than we were reading in since we did not understand the function
used to convert our advertised window to network byte order. This meant that we were not reading the full packets sent
to us, and therefore we were acking values that were too small.


Work breakdown:

As mentioned earlier, Tae-Hyeon took the lead for the IP layer and Mitchell took the lead for the TCP layer research.
We then began implementing the respective separate layers on our own, and once Tae-Hyeon's IP layer was ready to merge
we merged them together. From there on out we both worked together as there was a lot of error handling and bug fixing
that was much more efficiently handled with two sets of eyes thinking through where the issues were and strategies to
handle them.
