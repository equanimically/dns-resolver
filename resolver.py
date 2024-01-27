# The server code for a DNS resolver
#
# Written by Ace Mikunda on 04-08-2022
import sys
import socket
import threading

from client import construct_query, parse_response, TYPE_CNAME, TYPE_A

# Prints the usage information when invalid arguments are provided.
def print_usage():
    print("Error: invalid arguments")
    print("Usage: resolver port")

# Processes the command-line arguments and extracts the port number for the resolver.
#     Returns: The port number for the resolver.
def process_args():
    if len(sys.argv) != 2:
        print_usage()
        sys.exit(1)
    port = int(sys.argv[1])
    if not (1024 <= port <= 65535):
        print("Error: port must be in the range 1024 - 65535")
        sys.exit(1)
    return port

# Reads the 'named.root' file to get a list of nameservers and their IP addresses.
#     Returns: A list of IP addresses of the nameservers.
def get_nameservers_from_file():
    file_path = 'named.root'
    nameservers = {}
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith(';') or line == '\n':
                continue
            line_parts = line.split()
            if line_parts[2] == 'NS':   # Only consider NS records
                nameserver = line_parts[3]
                nameservers[nameserver] = None
            elif line_parts[0] in nameservers and line_parts[2] == 'A':
                nameservers[line_parts[0]] = line_parts[3]  # Found the IP address for a nameserver

    # Remove any nameservers for which we didn't find an IP address
    nameservers = {k: v for k, v in nameservers.items() if v is not None}
    return list(nameservers.values())

# Sends a DNS query to the specified IP address and returns the response.
#     Returns: The DNS response received from the nameserver.
def send_query(ip_address, query):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.sendto(query, (ip_address, 53))
            response, _ = s.recvfrom(1024)
            return response
        except socket.error as e:
            print(f"Server failure with {ip_address}. Error: {e}")
            return None


# Starts the DNS resolver on the specified port to listen for incoming queries.
def start_resolver(port):
    nameservers = get_nameservers_from_file()
    resolver_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    resolver_socket.bind(('localhost', port))

    while True:
        query, client_address = resolver_socket.recvfrom(1024)
        # Create a new thread for each request
        threading.Thread(target=resolve_request, args=(nameservers, query, client_address, resolver_socket)).start()

# Resolves a DNS query by forwarding it to the appropriate nameserver and handles CNAME chaining.
def resolve_request(nameservers, query, client_address, resolver_socket):
    i = 0
    server = nameservers[i]
    while i < len(nameservers):
        # send query to the first nameserver
        response = send_query(server, query)

        # If there was a server error and there are no more servers, report error to the client
        if response is None:
            if i == len(nameservers) - 1:
                error_msg = f"Server failure: All servers exhausted while trying to resolve {query}."
                resolver_socket.sendto(error_msg.encode(), client_address)
                return
            else:
                i += 1
                server = nameservers[i]
                continue

        # parse response
        parsed_response = parse_response(response)

        # if answer section is not empty and contains an A or CNAME record, send response to client
        if parsed_response['answers']:
            for answer in parsed_response['answers']:
                if answer['type'] == TYPE_A or answer['type'] == TYPE_CNAME:
                    resolver_socket.sendto(response, client_address)

                if answer['type'] == TYPE_CNAME:
                    cname = answer['rdata'].decode('utf-8')
                    query = construct_query(cname)  # update query to cname
                    server = nameservers[0]  # restart query process from the first nameserver
                    i = 0
                    break

            # After forwarding the response, if it had an A record, return
            if answer['type'] == TYPE_A:
                return

        # if auth section is not empty, send query to the first nameserver in auth section
        elif parsed_response['authorities']:
            server = decode_if_bytes(parsed_response['authorities'][0]['rdata'])

        # if auth section is empty, send query to the first nameserver in add section
        elif parsed_response['additionals']:
            server = decode_if_bytes(parsed_response['additionals'][0]['rdata'])

        i += 1


# Decodes the server information if it's in bytes format.
#     Returns: The decoded server information.
def decode_if_bytes(server):
    return server.decode('utf-8') if isinstance(server, bytes) else server

def main():
    port = process_args()
    start_resolver(port)

if __name__ == "__main__":
    main()