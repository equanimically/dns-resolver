# The client code for a DNS resolver
#
# Written by Ace Mikunda on 04-08-2022

import sys
import socket
import random
import struct
from io import BytesIO

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
CLASS_IN = 1
QR_SHIFT = 15
OPCODE_SHIFT = 11
AA_SHIFT = 10
TC_SHIFT = 9

# Prints the usage information when invalid arguments are provided.
def print_usage():
    print("Error: invalid arguments")
    print("Usage: client resolver_ip resolver_port name")

# Processes the command-line arguments and extracts resolver_ip, resolver_port, and name.
def process_args():
    if len(sys.argv) != 4:
        print_usage()
        sys.exit(1)

    resolver_ip = sys.argv[1]
    resolver_port = int(sys.argv[2])
    name = sys.argv[3]

    return resolver_ip, resolver_port, name

# Creates a DNS header with a random ID for the query.
def create_header():
    id = random.randint(0, 65535)
    return struct.pack('!HHHHHH', id, 0, 1, 0, 0, 0)

# Creates a DNS question section for the query using the given name.
#     Returns: A byte string representing the DNS question section.
def create_question(name):
    qname = name
    qtype = TYPE_A
    qclass = CLASS_IN

    return qname + struct.pack('!HH', qtype, qclass)

# Encodes the domain name into the DNS format.
#     Returns: A byte string representing the encoded domain name.
def encode_name(name):
    encoded_domain = b""
    for segment in name.encode("ascii").split(b"."):
        encoded_domain += bytes([len(segment)]) + segment
    return encoded_domain + b"\x00"

# Decodes the domain name from the DNS format.
#     Returns: The decoded domain name (bytes).
def decode_domain_name(byte_stream):
    domain_parts = []
    while (part_length := byte_stream.read(1)[0]) != 0:
        if part_length & 0b1100_0000:
            domain_parts.append(decompress_domain_name(part_length, byte_stream))
            break
        else:
            domain_parts.append(byte_stream.read(part_length))
    return b".".join(domain_parts)

# Decompresses the domain name from the DNS format using a pointer.
#     Returns: The decompressed domain name (bytes).
def decompress_domain_name(length, byte_stream):
    pointer_bytes = bytes([length & 0b0011_1111]) + byte_stream.read(1)
    pointer = struct.unpack("!H", pointer_bytes)[0]
    current_pos = byte_stream.tell()
    byte_stream.seek(pointer)
    result = decode_domain_name(byte_stream)
    byte_stream.seek(current_pos)
    return result

# Constructs a complete DNS query using the given domain name.
#     Returns: A byte string representing the complete DNS query (bytes).
def construct_query(name):
    encoded_name = encode_name(name)
    return create_header() + create_question(encoded_name)

# Parses the DNS header from the DNS response.
#     Returns: A dictionary containing various header fields from the DNS response.
def parse_header(byte_stream):
    unpacked_items = struct.unpack("!HHHHHH", byte_stream.read(12))

    flags = unpacked_items[1]
    qr = (flags & 0b1000000000000000) >> QR_SHIFT
    opcode = (flags & 0b0111100000000000) >> OPCODE_SHIFT
    aa = (flags & 0b0000010000000000) >> AA_SHIFT
    tc = (flags & 0b0000001000000000) >> TC_SHIFT
    rcode = flags & 0b0000000000001111

    return {
        "id": unpacked_items[0],
        "flags": flags,
        "qr": qr,
        "opcode": opcode,
        "aa": aa,
        "tc": tc,
        "rcode": rcode,
        "num_q": unpacked_items[2],
        "num_ans": unpacked_items[3],
        "num_auth": unpacked_items[4],
        "num_add": unpacked_items[5],
    }

# Parses the DNS question section from the DNS response.
#     Returns: A dictionary containing the parsed question information.
def parse_question(byte_stream):
    qname = decode_domain_name(byte_stream)
    qtype, qclass = struct.unpack("!HH", byte_stream.read(4))
    return {
        "qname": qname,
        "qtype": qtype,
        "qclass": qclass,
    }

# Parses a DNS resource record from the DNS response.
#     Returns: A dictionary containing the parsed resource record information.
def parse_record(byte_stream):
    name = decode_domain_name(byte_stream)
    rdata = byte_stream.read(10)
    rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", rdata)
    if rtype == TYPE_NS or rtype == TYPE_CNAME:
        rdata = decode_domain_name(byte_stream)
    elif rtype == TYPE_A:
        rdata = make_string_ip(byte_stream.read(rdlength))
    else:
        rdata = byte_stream.read(rdlength)

    return {
        "name": name,
        "type": rtype,
        "class": rclass,
        "ttl": ttl,
        "rdlength": rdlength,
        "rdata": rdata,
    }

# Parses the complete DNS response into a structured format.
#     Returns: A dictionary containing the parsed response including header, questions,
#     answers, authorities, and additionals.
def parse_response(res):
    byte_stream = BytesIO(res)
    header = parse_header(byte_stream)
    questions = [parse_question(byte_stream) for _ in range(header["num_q"])]
    answers = [parse_record(byte_stream) for _ in range(header["num_ans"])]
    authorities = [parse_record(byte_stream) for _ in range(header["num_auth"])]
    additionals = [parse_record(byte_stream) for _ in range(header["num_add"])]

    return {
        "header": header,
        "questions": questions,
        "answers": answers,
        "authorities": authorities,
        "additionals": additionals,
    }

# Converts a DNS record type code to its corresponding string representation.
#     Returns: The string representation of the DNS record type.
def record_to_string(type_code):
    type_dict = {
        1: "A",
        2: "NS",
        5: "CNAME",
    }
    return type_dict.get(type_code, "UNKNOWN")

# Converts a byte string representing an IP address to its dotted-decimal string representation.
#      Returns: The dotted-decimal string representation of the IP address.
def make_string_ip(ip):
    return ".".join(str(byte) for byte in ip)

# Creates a UDP socket for DNS communication.
#   Returns: A UDP socket object.
def create_socket():
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Transmits the DNS query to the DNS resolver.
def transmit_query(client_socket, resolver_ip, resolver_port, name):
    query = construct_query(name)
    client_socket.sendto(query, (resolver_ip, resolver_port))

# Collects DNS responses from the resolver until all answers are received or truncation occurs.
#     Returns: A tuple containing all_questions (list), all_answers (list), and the final response (dict).
def collect_responses(client_socket):
    all_questions = []
    all_answers = []
    while True:
        data, _ = client_socket.recvfrom(1024)
        response = parse_response(data)

        # Added error handling
        rcode = response["header"]["rcode"]
        if rcode == 1:
            print(f"Error: Format error. The name server was unable to interpret the query for {all_questions[0]['qname'].decode('utf-8')}")
            sys.exit(1)
        elif rcode == 2:
            print("Error: Server failure. The name server was unable to process this query due to a problem with the name server.")
            sys.exit(1)
        elif rcode == 3:
            print(f"Error: server can't find {all_questions[0]['qname'].decode('utf-8')}")
            sys.exit(1)
        elif rcode > 3:
            print(f"Error: Response code {rcode}")
            sys.exit(1)

        all_questions.extend(response["questions"])
        all_answers.extend(response["answers"])

        if not any(answer["type"] == TYPE_CNAME for answer in response["answers"]):
            break

    return all_questions, all_answers, response

# Prints the DNS question section of the response.
def print_question(all_questions):
    print(";; QUESTION SECTION:")
    question = all_questions[0]
    print(";{:<30}\tIN\t{}".format(question["qname"].decode("utf-8"), record_to_string(question["qtype"])))

# Prints the DNS answer section of the response.
def print_answers(all_answers):
    print("\n;; ANSWER SECTION:")
    for answer in all_answers:
        data_str = answer["rdata"].decode("utf-8") if isinstance(answer["rdata"], bytes) else answer["rdata"]
        print("{:<30}\tIN\t{}\t{}".format(answer["name"].decode("utf-8"), record_to_string(answer["type"]), data_str))

# Prints the DNS authority section of the response and whether the response is authoritative.
def print_authority_section(response):
    if response["header"]["aa"] == 1 and response["authorities"]:
        print("\n;; AUTHORITY SECTION:")
        print("The response is authoritative.")
    else:
        print("\n;; AUTHORITY SECTION:")
        print("The response is not authoritative.")

# Prints whether the DNS response was truncated or not.
def print_truncation_status(response):
    if response["header"]["tc"] == 1:
        print("\n;; The message was truncated.")
    else:
        print("\n;; The message was not truncated.")

# Starts the DNS client, transmits the query to the resolver, collects responses, and prints the results.
def start_client(resolver_ip, resolver_port, name):
    client_socket = create_socket()

    transmit_query(client_socket, resolver_ip, resolver_port, name)

    all_questions, all_answers, response = collect_responses(client_socket)

    client_socket.close()

    print_question(all_questions)
    print_answers(all_answers)
    print_authority_section(response)
    print_truncation_status(response)

def main():
    resolver_ip, resolver_port, name = process_args()
    start_client(resolver_ip, resolver_port, name)

if __name__ == "__main__":
    main()