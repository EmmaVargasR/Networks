import socket # Import Python's built-in socket module to create a TCP socket

HOST = '3.21.231.105' # The public IPv4 address of your AWS EC2 instance
PORT = 12345 # The port number to connect to

s = socket.socket() # Create a TCP socket for the client. Default arguments: socket.AF_INET (IPv4), socket.SOCK_STREAM (TCP)
s.connect((HOST, PORT)) # Connect to the server using the specified network address and port. Behind the scenes, this method performs a three-way handshake to establish a TCP connection with the server. If the server is not reachable or the connection fails, an exception will be raised.
data = s.recv(1024) # Establish a connection with the server and receive data. Maximum number of bytes to receive per reading block. If the server sends more data than this limit, the remaining data will be discarded. The recv() method blocks until data is received or the connection is closed by the server. If the connection is closed, it returns an empty bytes object (b'').
print("Received:", data.decode()) # Decode the received bytes object into a string using UTF-8 encoding and print it to the console. The decode() method converts the bytes into a human-readable string format.
s.close() # Close the socket connection to the server. This is important to free up system resources and avoid potential issues with too many open connections. After closing, the socket object can no longer be used for communication.
