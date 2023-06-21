#!/usr/bin/env python3

import socket

HOST = 'david.choffnes.com'
PORT = 80
REQUEST = "GET /classes/cs5700f22/50MB.log HTTP/1.1\r\nHost: david.choffnes.com\r\n\r\n"
FILENAME = '50http.log'
CHUNK_SIZE = 1024

if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(REQUEST.encode())
        with open(FILENAME, 'wb') as f:
            # Read and discard the response header
            response = b''
            while True:
                data = s.recv(CHUNK_SIZE)
                response += data
                if b'\r\n\r\n' in response:
                    break

            # Write any remaining data after the header to the file
            f.write(response[response.index(b'\r\n\r\n') + 4:])
            while True:
                data = s.recv(CHUNK_SIZE)
                if not data:
                    break
                f.write(data)
