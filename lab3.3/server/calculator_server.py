# calculator_server.py

import json  # JSON parsing and serialization
import socket  # TCP socket communication
import sys  # Command-line arguments

# Configurable port and host:
# Running 'python3 calculator_server.py' -> HOST="0.0.0.0", PORT=12345
# Running 'python3 calculator_server.py 12345' -> HOST="0.0.0.0", PORT=12345
# Running 'python3 calculator_server.py 12345 0.0.0.0' -> HOST="0.0.0.0", PORT=12345
if len(sys.argv) == 2:
    HOST = "0.0.0.0"
    PORT = int(sys.argv[1])
elif len(sys.argv) > 2:
    PORT = int(sys.argv[1])
    HOST = sys.argv[2]
else:
    HOST = "0.0.0.0"
    PORT = 12345


def print_log(client_ip, operation, a, b, result, error, code):
    """Log the operation details for evaluation and grading rubric."""
    print("=" * 55)
    print("Transaction Log:")
    print(f"  > Server IP    : {HOST}:{PORT}")
    print(f"  > Client IP    : {client_ip}")
    print(f"  > Operation    : {operation}")
    print(f"  > Parameters   : a = {a}, b = {b}")
    print(f"  > Result       : {result}")
    print(f"  > Error        : {error}")
    print(f"  > Code         : {code}")
    print("=" * 55)


def handle_request(data, client_ip):  # Process one client request
    try:
        payload = json.loads(data)  # Convert JSON string into dictionary

        # TODO 1: Check if any required parameter is missing
        if not isinstance(payload, dict):
            error_msg = "Invalid request: Payload must be a JSON object"
            print_log(client_ip, None, None, None, None, error_msg, 400)
            return {"result": None, "error": error_msg, "code": 400}

        required_fields = ["a", "b", "operation"]
        if not all(field in payload for field in required_fields):
            error_msg = "Invalid request: Missing required parameters"
            print_log(
                client_ip,
                payload.get("operation") if isinstance(payload, dict) else None,
                None,
                None,
                None,
                error_msg,
                400,
            )
            return {"result": None, "error": error_msg, "code": 400}

        a = payload.get("a")  # Get first value
        b = payload.get("b")  # Get second value
        operation = payload.get("operation")  # Get requested operation

        # Test 1: Check for empty string parameters (Invalid request -> 400)
        if isinstance(a, str) and a.strip() == "":
            error_msg = "Invalid request: Parameter 'a' cannot be empty"
            print_log(client_ip, operation, a, b, None, error_msg, 400)
            return {"result": None, "error": error_msg, "code": 400}

        if isinstance(b, str) and b.strip() == "":
            error_msg = "Invalid request: Parameter 'b' cannot be empty"
            print_log(client_ip, operation, a, b, None, error_msg, 400)
            return {"result": None, "error": error_msg, "code": 400}

        if isinstance(operation, str) and operation.strip() == "":
            error_msg = "Invalid request: Parameter 'operation' cannot be empty"
            print_log(client_ip, operation, a, b, None, error_msg, 400)
            return {"result": None, "error": error_msg, "code": 400}

        # Validate that operation, a, and b are received as strings
        if not isinstance(a, str) or not isinstance(b, str) or not isinstance(operation, str):
            error_msg = "Invalid input: 'a', 'b' and 'operation' must be strings"
            print_log(client_ip, operation, a, b, None, error_msg, 422)
            return {"result": None, "error": error_msg, "code": 422}

        # TODO 2: Validate that a and b can be converted to numbers (int, or float)
        # Test 5: Invalid values for a or b (e.g. "abc") -> Invalid input -> 422
        try:
            num_a = float(a)
            num_b = float(b)
            if num_a.is_integer():
                num_a = int(num_a)
            if num_b.is_integer():
                num_b = int(num_b)
        except ValueError:
            error_msg = "Invalid input: 'a' and 'b' must be numeric values"
            print_log(client_ip, operation, a, b, None, error_msg, 422)
            return {"result": None, "error": error_msg, "code": 422}

        # TODO 3: Implement the supported operations (add, sub, mul, div)
        op = operation.strip().lower()

        if op in ["add", "addition"]:
            res = num_a + num_b
        elif op in ["sub", "subtraction"]:
            res = num_a - num_b
        elif op in ["mul", "multiplication"]:
            res = num_a * num_b
        elif op in ["div", "division"]:
            # TODO 4: Handle division by zero
            # Test 3: Division by zero returns error 422
            if num_b == 0:
                error_msg = "Invalid input: Division by zero is not allowed"
                print_log(client_ip, operation, num_a, num_b, None, error_msg, 422)
                return {"result": None, "error": error_msg, "code": 422}
            res = num_a / num_b
        else:
            # TODO 5: Handle unsupported operations
            # Test 4: Unsupported operation (e.g. "sqrt") -> Invalid request -> 400
            error_msg = f"Invalid request: Unsupported operation '{operation}'"
            print_log(client_ip, operation, num_a, num_b, None, error_msg, 400)
            return {"result": None, "error": error_msg, "code": 400}

        # TODO 6: Return a successful response using the standardized format
        # Test 2: Valid operations return code 200
        print_log(client_ip, operation, num_a, num_b, res, None, 200)
        return {"result": res, "error": None, "code": 200}

    except json.JSONDecodeError:
        # TODO 7: Return an appropriate error for invalid JSON -> 400
        error_msg = "Invalid request: Malformed JSON"
        print_log(client_ip, None, None, None, None, error_msg, 400)
        return {"result": None, "error": error_msg, "code": 400}

    except Exception as e:
        # Unexpected server error -> 500
        error_msg = f"Unexpected server error: {str(e)}"
        print_log(client_ip, None, None, None, None, error_msg, 500)
        return {"result": None, "error": error_msg, "code": 500}


# Create TCP socket
server_socket = socket.socket()  # Create IPv4 TCP socket
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Enable address reuse
server_socket.bind((HOST, PORT))  # Bind socket to IP and port
server_socket.listen(5)  # Start listening for connections

print(f"Calculator server running on {HOST}:{PORT}")  # Display server status

while True:  # Keep server running
    conn, addr = server_socket.accept()  # Accept incoming connection
    print(f"Connection from {addr}")  # Display client address
    data = conn.recv(1024).decode()  # Receive client data
    response = handle_request(data, addr[0])  # Process request on server
    response_json = json.dumps(response)  # Convert response to JSON
    conn.send(response_json.encode())  # Send response to client
    conn.close()  # Close client connection
