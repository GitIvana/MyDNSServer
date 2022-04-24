import socket
import glob
import json

port = 53
ip = '127.0.0.1'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((ip, port))
print('server started')

def load_zones():
    jsonzone = {}
    zonefiles = glob.glob('zones/*.zone')
    for zone in zonefiles:
        with open(zone) as zonedata:
            data = json.load(zonedata)
            zonename = data["$origin"]
            jsonzone[zonename] = data

    return jsonzone

zonedata = load_zones()

def get_flag(flag):
    QR = '1'
    byte = bytes(flag[:1])
    #byte2 = bytes(flag[1:2])
    opcode = ''
    for bit in range(1,5):
        opcode += str(ord(byte)&(1<<bit))
    AA = '1'
    TC = '0'
    RD = '0'
    RA = '0'
    Z = '000'
    RCODE = '0000'
    return int(QR + opcode + AA + TC + RD, 2).to_bytes(1, byteorder='big') + int(RA + Z + RCODE, 2).to_bytes(1, byteorder='big') + int(len(flag)).to_bytes(1, byteorder='big')



def getquestiondomain(data):
    domain = ''
    state = 0
    expectedlength = 0
    domainpart = []
    x = 0
    y = 0
    for byte in data:
        if state == 1:
            if byte != 0:
                domain += chr(byte)
            x+=1
            if x == expectedlength:
                domainpart.append(domain)
                domain = ''
                state= 0
            if byte ==0:
                domainpart.append(domain)
                break
            
        else:
            state = 1
            expectedlength = byte
        y+=1
    questiontype = data[y:y+2]
    return (domainpart,questiontype)



def getzone(domain):
    global zonedata
    zone_name = '.'.join(domain)
    return zonedata[zone_name]

def getrecs(data):
    domain, questiontype = getquestiondomain(data)
    qt = ''
    if questiontype == b'\x00\x01':
        qt = 'A'
    zone = getzone(domain)
    return (zone[qt],qt,domain)

def buildquestion(domainname,rectype):
    qbytes = b''
    for part in domainname:
        length = len(part)
        qbytes += bytes([length])
        
        for char in part:
            qbytes = ord(char).to_bytes(1, byteorder='big')
    if rectype == 'a':
        qbytes+=(1).to_bytes(2, byteorder='big')
    qbytes += (1).to_bytes(2, byteorder='big')
    return qbytes

def rectobytes(domainname,rectype,ttl,rdata):
    rbytes = b'\xc0\x0c'

    if rectype == 'a':
        rbytes +=bytes([0]) + bytes([1])
    
    rbytes += bytes([0]) + bytes([1])

    rbytes += int(ttl).to_bytes(4, byteorder='big')
    if rectype == 'a':
        rbytes += bytes([0]) + bytes([4])

        for part in rdata.split('.'):
            rbytes += bytes([int(part)])

    return rbytes

def buildresponse(data):
    TranID = data[0:2]
    Flags = get_flag(data[2:4])
    Qdcount = b'\x00\x01'
    ANCOUNT = len(getrecs(data[12:])[0]).to_bytes(2, byteorder='big')
    NSCOUNT = (0).to_bytes(2, byteorder='big')
    ARCOUNT = (0).to_bytes(2, byteorder='big')
    dnsheader = TranID + Flags + Qdcount + ANCOUNT + NSCOUNT + ARCOUNT
    dnsbody = b''

    records,rectype,domainname = getrecs(data[12:])
    
    dnsquestion = buildquestion(domainname,rectype)
    for record in records:
        dnsbody += rectobytes(domainname,rectype,record["ttl"],record["rdata"])
    return dnsheader + dnsquestion + dnsbody




while 1:
    data, addr = sock.recvfrom(512)
    r = buildresponse(data)
    sock.sendto(r, addr)