#!/usr/bin/env python3
"""Minimal DNS resolver from scratch."""
import socket,struct,argparse,random
def build_query(domain,qtype=1):
    tid=random.randint(0,65535);flags=0x0100;questions=1
    header=struct.pack(">HHHHHH",tid,flags,questions,0,0,0)
    qname=b""
    for part in domain.split("."): qname+=bytes([len(part)])+part.encode()
    qname+=b"\x00"
    question=qname+struct.pack(">HH",qtype,1)
    return header+question
def parse_response(data):
    tid,flags,qdcount,ancount=struct.unpack(">HHHH",data[:8])
    offset=12
    for _ in range(qdcount):
        while data[offset]!=0:
            offset+=data[offset]+1
        offset+=5
    answers=[]
    for _ in range(ancount):
        if data[offset]&0xC0==0xC0: offset+=2
        else:
            while data[offset]!=0: offset+=data[offset]+1
            offset+=1
        atype,aclass,ttl,rdlen=struct.unpack(">HHIH",data[offset:offset+10]);offset+=10
        if atype==1 and rdlen==4:
            ip=".".join(str(b) for b in data[offset:offset+4])
            answers.append({"type":"A","ip":ip,"ttl":ttl})
        offset+=rdlen
    return answers
def resolve(domain,server="8.8.8.8"):
    query=build_query(domain);sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.settimeout(3);sock.sendto(query,(server,53));data,_=sock.recvfrom(512);sock.close()
    return parse_response(data)
def main():
    p=argparse.ArgumentParser();p.add_argument("domain");p.add_argument("-s","--server",default="8.8.8.8")
    a=p.parse_args()
    for ans in resolve(a.domain,a.server): print(f"  {ans['type']}: {ans['ip']} (TTL {ans['ttl']})")
if __name__=="__main__": main()
