import socket, struct, io, os, sys, json
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
def vi(n):
    o=b''
    while True:
        b=n&0x7f; n>>=7; o+=bytes([b|(0x80 if n else 0)])
        if not n: return o
def s_(x): x=x.encode(); return vi(len(x))+x
def arr(x): return vi(len(x))+x
def pkt(d): return vi(len(d))+d
class R:
    def __init__(s,sock): s.sock=sock; s.dec=None
    def byte(s):
        b=s.sock.recv(1)
        if not b: raise EOFError("server closed the connection")
        return s.dec.update(b) if s.dec else b
    def vi(s):
        n=sh=0
        while True:
            x=s.byte()[0]; n|=(x&0x7f)<<sh; sh+=7
            if not x&0x80: return n
    def packet(s):
        ln=s.vi(); return io.BytesIO(b''.join(s.byte() for _ in range(ln)))
def bvi(b):
    n=sh=0
    while True:
        x=b.read(1)[0]; n|=(x&0x7f)<<sh; sh+=7
        if not x&0x80: return n
mode=sys.argv[1]; proto=int(sys.argv[2]) if len(sys.argv)>2 else 760
sock=socket.create_connection(("127.0.0.1",25565),10); r=R(sock)
sock.send(pkt(vi(0)+vi(proto)+s_("localhost")+struct.pack('>H',25565)+vi(2)))
sock.send(pkt(vi(0)+s_("ProbeTest")+(b"\x00" if proto==759 else b"\x00\x00"))) 
p=r.packet(); pid=bvi(p); print("got packet id", pid, "(1 = encryption request)")
sid=p.read(bvi(p)); pub=p.read(bvi(p)); tok=p.read(bvi(p))
key=load_der_public_key(pub); secret=os.urandom(16)
enc=lambda d: key.encrypt(d, padding.PKCS1v15())
if mode=="token":
    body=vi(1)+arr(enc(secret))+b'\x01'+arr(enc(tok))
else:
    body=vi(1)+arr(enc(secret))+b'\x00'+struct.pack('>q',12345)+arr(os.urandom(256))
sock.send(pkt(body))
c=Cipher(algorithms.AES(secret), modes.CFB8(secret)); r.dec=c.decryptor()
try:
    p=r.packet(); pid=bvi(p); msg=p.read(bvi(p)).decode()
    print("server reply: packet", pid, "->", msg)
except EOFError as e:
    print("no reply:", e)
