import sys
import socket
import struct
import random

class Resolver:
    def __init__(self):
        self.root_servers = {}

    def print_usage(self):
        print("Error: invalid arguments")
        print("Usage: resolver port")

    def parse_arguments(self):
        if len(sys.argv) != 2:
            self.print_usage()
            sys.exit(1)
        
        port = int(sys.argv[1])

        if not (1024 <= port <= 65535):
            print("Error: port must be in the range 1024 - 65535")
            sys.exit(1)

        return port

    def read_root_hints(self):
        with open('named.root', 'r') as file:
            for line in file:
                if line.startswith(';') or line == '\n':
                    continue
                line = line.split()
                if line[3] != 'A':  # we ignore AAAA records
                    continue
                self.root_servers[line[0]] = line[4]

    def construct_dns_query(self, name):
        id = random.randint(0, 65535)
        flags = 0  # standard query, recursion not desired
        qdcount = 1  # number of questions
        ancount = nscount = arcount = 0  # number of answer, authority, and additional RRs
        query = struct.pack('!HHHHHH', id, flags, qdcount, ancount, nscount, arcount)
        query += self.encode_domain_name(name)
        qtype = 1  # type A
        qclass = 1  # class IN
        query += struct.pack('!HH', qtype, qclass)
        return query

    def encode_domain_name(self, name):
        labels = name.split('.')
        encoded_name = b''
        for label in labels:
            encoded_name += struct.pack('B', len(label))
            encoded_name += label.encode()
        encoded_name += struct.pack('B', 0)  # end of name
        return encoded_name

    def process_query(self, query):
        # Parse the client's query and extract the requested domain name
        id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', query[:12])
        pos = 12
        labels = []
        while True:
            length, = struct.unpack('B', query[pos:pos+1])
            pos += 1
            if length == 0:
                break
            labels.append(query[pos:pos+length].decode())
            pos += length
        name = '.'.join(labels)

        # Start the resolution process from the root servers
        for root_server in self.root_servers.values():
            print(f'Querying root server {root_server} for {name}')
            server_address = (root_server, 53)
            query = self.construct_dns_query(name)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(query, server_address)
                response, _ = s.recvfrom(1024)
            # Simplified processing of the response: just return it to the client
            return response

    def start(self):
        port = self.parse_arguments()
        self.read_root_hints()

        # create socket for resolver
        resolver_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # bind socket to port and localhost address
        resolver_socket.bind(('localhost', port))

        # listen for incoming connections
        print('Resolver is listening on port', port)

        while True:
            # receive query from client
            query, client_address = resolver_socket.recvfrom(1024)
            print('Received query from client:', query)

            # Process the query and prepare the response
            response = self.process_query(query)

            # Send the response back to the client
            resolver_socket.sendto(response, client_address)

    def main(self):
        self.start()

if __name__ == "__main__":
    resolver = Resolver()
    resolver.main()
