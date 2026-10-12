# calculator_client.py

import json  # JSON serialization
import socket  # TCP socket communication
import sys  # Command-line arguments for configurable IP and port

# Server connection parameters (can be configured via CLI or fallback to defaults)
HOST = sys.argv[1] if len(sys.argv) > 1 else "3.21.231.105"  # Server IP address.
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 12345  # Server port

a = input("Enter first number: ")  # Read first value as text
b = input("Enter second number: ")  # Read second value as text
operation = input("Enter operation (add, sub, mul, div): ")  # Read operation as text

payload = {  # Create request dictionary without client-side validations
    "a": a,  # Store first value
    "b": b,  # Store second value
    "operation": operation,  # Store requested operation
}

s = socket.socket()  # Create TCP socket
try:
    s.connect((HOST, PORT))  # Connect to server
    # Serialize and send request
    s.send(json.dumps(payload).encode())

    response = s.recv(1024).decode()  # Receive server response
    print("Server response:", response)  # Display raw JSON response

    # Parse and display fields directly without any conditional branching/comparison
    try:
        parsed_res = json.loads(response)
        print("-" * 35)
        print(f"Code    : {parsed_res.get('code')}")
        print(f"Result  : {parsed_res.get('result')}")
        print(f"Error   : {parsed_res.get('error')}")
        print("-" * 35)
    except json.JSONDecodeError:
        print("[!] Warning: Received non-JSON response from server.")

except Exception as e:
    print(f"[!] Connection error: {e}")
finally:
    s.close()  # Close connection immediately after one request/response cycle
