import sys
import socket
import random
import struct
from io import BytesIO

TYPE_A = 1
CLASS_IN = 1

def print_usage():
    print("Error: invalid arguments")
    print("Usage: client resolver_ip resolver_port name")


def parse_arguments():
    if len(sys.argv) != 4:
        print_usage()
        sys.exit(1)

    resolver_ip = sys.argv[1]
    resolver_port = int(sys.argv[2])
    name = sys.argv[3]

    return resolver_ip, resolver_port, name

def construct_dns_header():
    # Make DNS header
    id = random.randint(0, 65535)
    flags = 0
    num_questions = 1
    num_answers = 0
    num_authorities = 0
    num_additionals = 0

    # Convert header to bytes
    header = struct.pack('!HHHHHH', id, flags, num_questions, num_answers, num_authorities, num_additionals)

    return header


def construct_dns_question(name):
    # Make DNS question
    qname = name
    qtype = TYPE_A
    qclass = CLASS_IN

    # Convert question to bytes
    question = struct.pack('!HH', qtype, qclass)

    return qname + question


def encode_dns_name(name):
    encoded = b""
    for part in name.encode("ascii").split(b"."):
        encoded += bytes([len(part)]) + part
    return encoded + b"\x00"


def decode_name(reader):
    parts = []
    while (length := reader.read(1)[0]) != 0:
        if length & 0b1100_0000:
            parts.append(decode_compressed_name(length, reader))
            break
        else:
            parts.append(reader.read(length))
    return b".".join(parts)


def decode_compressed_name(length, reader):
    pointer_bytes = bytes([length & 0b0011_1111]) + reader.read(1)
    pointer = struct.unpack("!H", pointer_bytes)[0]
    current_pos = reader.tell()
    reader.seek(pointer)
    result = decode_name(reader)
    reader.seek(current_pos)
    return result


def construct_dns_query(name):
    name = encode_dns_name(name)
    header = construct_dns_header()
    question = construct_dns_question(name)
    return header + question


def parse_header(reader):
    items = struct.unpack("!HHHHHH", reader.read(12))
    return {
        "id": items[0],
        "flags": items[1],
        "num_questions": items[2],
        "num_answers": items[3],
        "num_authorities": items[4],
        "num_additionals": items[5],
    }


def parse_question(reader):
    qname = decode_name(reader)
    data = reader.read(4)
    qtype, qclass = struct.unpack("!HH", data)
    return {
        "qname": qname,
        "qtype": qtype,
        "qclass": qclass,
    }


def parse_dns_record(reader):
    name = decode_name(reader)
    data = reader.read(10)
    type_, class_, ttl, rdlength = struct.unpack("!HHIH", data)
    data = reader.read(rdlength)
    return {
        "name": name,
        "type": type_,
        "class": class_,
        "ttl": ttl,
        "data": data,
    }


def parse_dns_response(response):
    reader = BytesIO(response)
    header = parse_header(reader)
    questions = [parse_question(reader) for _ in range(header["num_questions"])]
    answers = [parse_dns_record(reader) for _ in range(header["num_answers"])]
    authorities = [parse_dns_record(reader) for _ in range(header["num_authorities"])]
    additionals = [parse_dns_record(reader) for _ in range(header["num_additionals"])]
    return {
        "header": header,
        "questions": questions,
        "answers": answers,
        "authorities": authorities,
        "additionals": additionals,
    }

def ip_to_string(ip):
    return ".".join(str(byte) for byte in ip)
def start_client(resolver_ip, resolver_port, name):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    query = construct_dns_query(name)

    # Send the query to the resolver
    client_socket.sendto(query, (resolver_ip, resolver_port))

    # Receive the response from the resolver
    data, _ = client_socket.recvfrom(1024)
    response = parse_dns_response(data)
    client_socket.close()

    return ip_to_string(response["answers"][0]["data"])


def main():
    resolver_ip, resolver_port, name = parse_arguments()
    print(resolver_ip, resolver_port, name)

    start_client(resolver_ip, resolver_port, name)


if __name__ == "__main__":
    main()
