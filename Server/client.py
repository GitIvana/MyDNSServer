import socket
import sys

from socket import inet_ntop
from socket import AF_INET6
from struct import unpack_from
from collections import namedtuple

### Tuples for message parts
Header = namedtuple("Header", [
    'x_id',
    'qr',
    'opcode',
    'aa',
    'tc',
    'rd',
    'ra',
    'rcode',
    'qdcount',
    'ancount',
    'nscount',
    'arcount',
    ])

Question = namedtuple("Question", [
    'qname',
    'qtype',
    'qclass',
    ])

Answer = namedtuple("Answer", [
    'name',
    'x_type',
    'x_class',
    'ttl',
    'rdlength',
    'rdata',
    ])

Reply = namedtuple("Reply", [
    'header',
    'question',
    'answer',
    ])

def parse_answer(msg, qname_len):
    """ Function used to parse the DNS reply message.
        
    Args:
        msg: The message recieved from the DNS server
        qname_len: The length of the name beign querried
    Returns:
        The DNS reply message as a Reply namedtuple in the following
        form: (Header, Question, [Answer]).
    """

    header = extract_header(msg)
    question = extract_question(msg, qname_len)
    # 12 is header length and 4 is len(qtype) + len(qclass)
    offset = 12 + qname_len + 4 

    answer = []
    for _ in range(header.ancount):
        (a, offset) = extract_answer(msg, offset)
        answer.append(a)

    for _ in range(header.nscount):
        (a, offset) = extract_answer(msg, offset)
        answer.append(a)

    for _ in range(header.arcount):
        (a, offset) = extract_answer(msg, offset)
        answer.append(a)

    return Reply(header, question, answer)

def extract_header(msg):
    """ Function used to extract the header from the DNS reply message.
        
    Args:
        msg: The message recieved from the DNS server
    Returns:
        The header of the reply as a Header namedtuple in the following
        form: Header(x_id, qr, opcode, aa, tc, rd, ra, rcode, qdcount, 
        ancount, nscount, arcount)
    """

    raw_header = unpack_from(">HHHHHH", msg, 0)

    x_id = raw_header[0]
    flags = raw_header[1]

    qr = flags >> 15
    opcode = (flags & 0x7800) >> 11
    aa = (flags & 0x0400) >> 10
    tc = (flags & 0x0200) >> 9
    rd = (flags & 0x0100) >> 8
    ra = (flags & 0x0080) >> 7
    rcode = (flags & 0x000f)

    qdcount = raw_header[2]
    ancount = raw_header[3]
    nscount = raw_header[4]
    arcount = raw_header[5]

    return Header(x_id, qr, opcode, aa, tc, rd, ra, rcode, qdcount, ancount, nscount, arcount)


def extract_question(msg, qname_len):
    """ Function used to extract the question section from a DNS reply.
        
    Args:
        msg: The message recieved from the DNS server
        qname_len: The length of the name beign querried
    Returns:
        The question section of the reply as a Question namedtuple in the 
        following form: Question(qname, qtype, qclass)
    """

    # 12 is len(header_section)
    offset = 12

    # qname
    raw_qname = []
    for i in range(0, qname_len):
        byte = unpack_from(">B", msg, offset + i)[0]
        raw_qname.append(byte)

    qname = convert_to_name(raw_qname)
    qtype = unpack_from(">H", msg, offset + qname_len)[0]
    qclass = unpack_from(">H", msg, offset + qname_len + 2)[0]

    return Question(qname, qtype, qclass)

def extract_answer(msg, offset):
    """ Function used to extract a RR from a DNS reply.
        
    Args:
        msg: The message recieved from the DNS server
        offset: The number of bytes from the start of the message until the end
            of the question section (or until the end of the last RR)
    Returns:
        The resource record section of the reply that begins at the given offset
        and the offset from the start of the message to where the returned RR
        ends in the following form: (Answer(name, x_type, x_class, ttl, rdlength, 
        rdata), offset)
    If the DNS Response is not implemented or recognized, an error message is
    shown and the program will exit.
    """

    (name, bytes_read) = extract_name(msg, offset)
    offset = offset + bytes_read

    aux = unpack_from(">HHIH", msg, offset)
    offset = offset + 10

    x_type = aux[0]
    x_class = aux[1]
    ttl = aux[2]
    rdlength = aux[3]

    rdata = ''
    if x_type == 1:
        # A type
        rdata = extract_a_rdata(msg, offset, rdlength)
        offset = offset + rdlength
    elif x_type == 2:
        # NS type
        rdata = extract_ns_rdata(msg, offset, rdlength)
        offset = offset + rdlength
    elif x_type == 5:
        # CNAME type
        rdata = extract_cname_rdata(msg, offset, rdlength)
        offset = offset + rdlength
    elif x_type == 6:
        # SOA type
        rdata = extract_soa_rdata(msg, offset, rdlength)
        offset = offset + rdlength
    elif x_type == 15:
        # MX type
        rdata = extract_mx_rdata(msg, offset, rdlength)
        offset = offset + rdlength
    elif x_type == 28:
        # AAAA type
        rdata = extract_aaaa_rdata(msg, offset, rdlength)
        offset = offset + rdlength
    else:
        print('[Error]: DNS Response not recognized (type ' + str(x_type) + '). Exiting...')
        exit(0)

    return (Answer(name, x_type, x_class, ttl, rdlength, rdata), offset)

def extract_a_rdata(msg, offset, rdlength):
    """ Function used to extract the RDATA from an A type message.
        
    Args:
        msg: The message recieved from the DNS server
        offset: The number of bytes from the start of the message until the end
            of the question section (or until the end of the last RR)
        rdlength: The length of the RDATA section
    Returns:
        The RDATA field of the answer section as a string (an IPv4 address).
    """

    fmt_str = ">" + "B" * rdlength
    rdata = unpack_from(fmt_str, msg, offset)

    ip = ''
    for byte in rdata:
        ip += str(byte) + '.'
    ip = ip[0:-1]

    return ip

def extract_ns_rdata(msg, offset, rdlength):
    """ Function used to extract the RDATA from a NS type message.
        
    Args:
        msg: The message recieved from the DNS server
        offset: The number of bytes from the start of the message until the end
            of the question section (or until the end of the last RR)
        rdlength: The length of the RDATA section
    Returns:
        The RDATA field of the answer section as a string and the offset from
        the start of the message until the end of the rdata field as a tuple:
        (rdata, field)
    """

    (name, bytes_read) = extract_name(msg, offset)
    offset += bytes_read

    return (name, offset)

def extract_cname_rdata(msg, offset, rdlength):
    """ Function used to extract the RDATA from a CNAME type message.
        
    Args:
        msg: The message recieved from the DNS server
        offset: The number of bytes from the start of the message until the end
            of the question section (or until the end of the last RR)
        rdlength: The length of the RDATA section
    Returns:
        The RDATA field of the answer section as a string and the offset from
        the start of the message until the end of the rdata field as a tuple:
        (rdata, field)
    """

    (name, bytes_read) = extract_name(msg, offset)
    offset += bytes_read

    return (name, offset)

def extract_soa_rdata(msg, offset, rdlength):
    """ Function used to extract the RDATA from a SOA type message.
        
    Args:
        msg: The message recieved from the DNS server
        offset: The number of bytes from the start of the message until the end
            of the question section (or until the end of the last RR)
        rdlength: The length of the RDATA section
    Returns:
        The RDATA field of the answer section as a tuple of the following form:
        (pns, amb, serial, refesh, retry, expiration, ttl)    
    """

    # extract primary NS
    (pns, bytes_read) = extract_name(msg, offset)
    offset += bytes_read
    # extract admin MB
    (amb, bytes_read) = extract_name(msg, offset)
    offset += bytes_read

    aux = unpack_from(">IIIII", msg, offset)

    serial = aux[0]
    refesh = aux[1]
    retry = aux[2]
    expiration = aux[3]
    ttl = aux[4]

    return (pns, amb, serial, refesh, retry, expiration, ttl)    

def extract_mx_rdata(msg, offset, rdlength):
    """ Function used to extract the RDATA from a MX type message.
        
    Args:
        msg: The message recieved from the DNS server
        offset: The number of bytes from the start of the message until the end
            of the question section (or until the end of the last RR)
        rdlength: The length of the RDATA section
    Returns:
        The RDATA field of the answer section as a tuple of the following form:
        (preference, mail_ex)
    """

    preference = unpack_from(">H", msg, offset)
    offset += 2
    
    fmt_str = ">" + "B" * (rdlength - 2)
    rdata = unpack_from(fmt_str, msg, offset)[0]

    mail_ex = ''
    for byte in rdata:
         mail_ex += chr(byte)
    mail_ex += '\x00'

    return (preference, mail_ex)

def extract_aaaa_rdata(msg, offset, rdlength):
    """ Function used to extract the RDATA from an AAAA type message.
        
    Args:
        msg: The message recieved from the DNS server
        offset: The number of bytes from the start of the message until the end
            of the question section (or until the end of the last RR)
        rdlength: The length of the RDATA section
    Returns:
        The RDATA field of the answer section (an IPv6 address as a string)
    """

    fmt_str = ">" + "H" * (rdlength / 2)
    rdata = unpack_from(fmt_str, msg, offset)

    ip = ''
    for short in rdata:
        ip += format(short, 'x') + ':'
    ip = ip[0:-1]

    return ip

def extract_name(msg, offset):
    """ Function used to extract the name field from the answer section.
    Args:
        msg: The message recieved from the DNS server
        offset: The number of bytes from the start of the message until the end
            of the question section (or until the end of the last RR)
        
    Returns: 
        Tuple containing the name and number of bytes read.
    """

    raw_name = []
    bytes_read = 1
    jump = False

    while True:
        byte = unpack_from(">B", msg, offset)[0]
        if byte == 0:
            offset += 1
            break

        # If the field has the first two bits equal to 1, it's a pointer
        if byte >= 192:
            next_byte = unpack_from(">B", msg, offset + 1)[0]
            # Compute the pointer
            offset = ((byte << 8) + next_byte - 0xc000) - 1
            jump = True
        else:
            raw_name.append(byte)

        offset += 1

        if jump == False:
            bytes_read += 1

    raw_name.append(0)
    if jump == True:
        bytes_read += 1

    name = convert_to_name(raw_name)

    return (name, bytes_read)

def convert_to_name(raw_name):
    """ Function used to convert an url from dns form to normal form.
    Args:
        The dns form of the url
    Returns:
        The normal form of the url
    Example: 
        3www7example3com0 to www.example.com
    """

    # might not work as expected in some cases - todo
    name = ''
    for byte in raw_name:
        if byte < 30:
            name += '.'
        else:
            name += chr(int(byte))

    name = name[1:-1]

    return name

def print_reply(reply):
    """ Function for printing a DNS message reply.
    Args:
        The parsed DNS reply
    """

    print("\n")
    print("Header Section")
    print("----------------")
    print    ("id: " + str(reply.header.x_id) 
            + ", qr: " + str(reply.header.qr) 
            + ", opcode: " + str(reply.header.opcode) 
            + ", rcode: " + str(reply.header.rcode))
    print    ("aa: " + str(reply.header.aa) 
            + ", tc: " + str(reply.header.tc) 
            + ", rd: " + str(reply.header.rd) 
            + ", ra: " + str(reply.header.ra))
    print    ("qdcount: " + str(reply.header.qdcount) 
            + ", ancount: " + str(reply.header.ancount) 
            + ", nscount: " + str(reply.header.nscount) 
            + ", arcount: " + str(reply.header.arcount))
    print ("\n")

    print ("Question Section")
    print ("----------------")
    print ("qname: " + str(reply.question.qname))
    print ("qtype: " + str(reply.question.qtype))
    print ("qclass: " + str(reply.question.qclass))
    print ("\n")

    print ("Answer Section")
    print ("----------------")
    for entry in reply.answer:
        print ("name: " + str(entry.name))
        print ("type: " + str(entry.x_type) + ", class: " + str(entry.x_class) 
            + ", ttl: " + str(entry.ttl) + ", rdlength: " + str(entry.rdlength) + ", rdata: ")

        if entry.x_type == 1:
            print(str(entry.rdata))
        elif entry.x_type == 2:
            print (str(entry.rdata))
        elif entry.x_type == 6:
            print (tuple_str(entry.rdata))
        elif entry.x_type == 15:
            print (tuple_str(entry.rdata))
        elif entry.x_type == 28:
            print (str(entry.rdata))
    print ("\n")

def tuple_str(t):
    """ Auxiliary function used for turning a tuple into a string.
    Args:
        The tuple
    Returns:
        The string form of the tuple
    """

    res = ''
    for i in t:
        res += str(i) + ' '

    return res

"""
    Module used for creating DNS queries.
"""

from struct import pack
from os import getpid

# Opcodes
QUERY = 0
IQUERY = 1
STATUS = 2

def create_header(opcode):
    """ Function used to create a DNS query header.
    
    Args:
        opcode = opcode of the query. It can take the following values:
            QUERY = 0, IQUERY = 1, STATUS = 2
    Returns:
        The header
    """

    header = ''
    flags = ''

    # Message ID
    header += str(pack(">H", getpid()))

    # Flags (QR, opcode, AA, TC, RD, RA, Z, RCODE)
    if opcode == QUERY:
        # Standard DNS query
        flags = 0b0000000100000000
    elif opcode == IQUERY:
        flags = 0b0000100100000000
    elif opcode == STATUS:
        flags = 0b0001000100000000

    header += str(pack(">H", flags))

    # QDCOUNT
    header += str(pack(">H", 1))
    # ANCOUNT
    header += str(pack(">H", 0))
    # NSCOUNT
    header += str(pack(">H", 0))
    # ARCOUNT
    header += str(pack(">H", 0))

    return header

def get_dns_query(domain_name, query_type):
    """ Function used to create a DNS query question section.
    
    Args:
        domain_name = the domain name that needs to be resolved
        query_type = the query type of the DNS message
    Returns:
        The DNS query question section and the length of the qname in a tuple
        form: (question, qname_len)
    """

    # QNAME
    qname = create_qname(domain_name)

    code = 0
    # QTYPE - query for A record
    if query_type == "A":
        # host address
        code = 1
    elif query_type == "NS":
        # authoritative name server
        code = 2
    elif query_type == "CNAME":
        # the canonical name for an alias
        code = 5
    elif query_type == "SOA":
        # start of a zone of authority
        code = 6
    elif query_type == "MX":
        # mail exchange
        code = 15
    elif query_type == "TXT":
        # text strings
        print ("[Error]: Not implemented. Exiting...")
        exit(1)
        code = 16
    elif query_type == "PTR":
        # domain name pointer
        code = 12
        print ("[Error]: Not implemented. Exiting...")
        exit(1)
    elif query_type == "AAAA":
        # AAAA record
        code = 28
    else:
        print ("[Error]: Invalid query. Exiting...")
        exit(1)

    qtype = str(pack(">H", code))

    # QCLASS - internet
    qclass = str(pack(">H", 1))

    # whole question section
    question = create_header(QUERY) + qname + qtype + qclass

    return (question, len(qname))

def create_qname(domain_name):
    """ Function used to transfrom URL from normal form to DNS form.
    Args:
        domain_name = URL that needs to be converted
    Returns:
        The URL in DNS form
    Example:
        3www7example3com0 to www.example.com
    """

    qname = ''

    split_name = domain_name.split(".")
    for atom in split_name:
        qname += str(pack(">B", len(atom)))
        for byte in bytes(atom,encoding='utf8'):
            qname += str(byte)
    qname += '\x00'

    return qname

def query_dns_server(packet):
    """ Function used to create a UDP socket, to send the DNS query to the server
        and to receive the DNS reply.
    Args:
        packet = the DNS query message
    
    Returns:
        The reply of the server
    If none of the servers in the dns_servers.conf sends a reply, the program
    exits showing an error message.
    """

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, True)
        sock.ioctl(socket.SIO_KEEPALIVE_VALS,(1,60*1000,30*1000))
    except socket.error:
        print ("[Error]: Faild to create socket. Exiting...")
        exit(1)

    # get DNS server IPs from dns_servers.conf file
    dns_servers = ['8.8.8.8']
    # default port for DNS
    server_port = 53

    for server_ip in dns_servers:
        got_response = False

        # send message to server
        sock.sendto(bytes(packet,encoding='utf8'), (server_ip, server_port))
        # receive answer
        recv = sock.recvfrom(512)

        # if no answer is received, try another server
        if recv:
            got_response = True
            break

    # output error message if no server could respond
    if not got_response:
        print ("[Error]: No response received from server. Exiting...")
        exit(0)

    return recv[0]

def main():
    """ Main function of the DNS client"""

    if len(sys.argv) != 3:
        print ("Usage: ./dnsclient.py <DNS name/IP> <query type>")
        exit(0)

    query_elem = sys.argv[1]
    query_type = sys.argv[2]

    ### Create packet according to the requested query
    packet = ""
    query = get_dns_query(query_elem, query_type)

    # query[0] is the packet
    packet = query[0]

    raw_reply = query_dns_server(packet)
    # query[1] is qname length
    reply = parse_answer(raw_reply, query[1])
    print_reply(reply)

    return 0

if __name__ == "__main__":
    while True:
        print("[Info]: Starting DNS client...")
        main()
        print("[Info]: DNS client finished.")
        print("[Info]: Do you want to send new queries? (y/n)")
        if input() == 'y':
            continue
        else:
            break

