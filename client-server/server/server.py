import socket # Import Python's built-in socket module to create a TCP socket

HOST = '0.0.0.0' # Listen on all available network interfaces (IP addresses)
PORT = 12345 # Defines the TCP port where the server will listen

s = socket.socket() # Create a TCP socket. Default arguments: socket.AF_INET (IPv4), socket.SOCK_STREAM (TCP)
s.bind((HOST, PORT)) # Bind the socket to the specified address and port
s.listen(1) # Start listening for incoming connections (1 pecifies the backlog, i.e. how many pending connections the OS can queue while the application is not yet accepting them)
print("TCP server waiting for connection...") # Print that the server is ready to accept connections
conn, addr = s.accept() # Accept an incoming connection. This method blocks until a connection is established. It returns a new socket object specifically for connecting with that client (conn), and the client's network address and port (addr)
print(f"Connected to {addr}") # Print the address of the connected client (addr is a tuple containing the client's IP address and port number)
conn.send(b"Hello Emma, from the EC2 server!") # Send a message to the connected client. The message must be in bytes, hence the 'b' prefix before the string
conn.close() # Close the connection with the client. This is important to free up system resources and avoid potential issues with too many open connections
