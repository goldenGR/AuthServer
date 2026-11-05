import socket, struct, io, os, sys, json, time
from cryptography.hazmat.primitives.serialization import load_der_public_key, Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
def vi(n):
    o=b''
    while True:
        b=n&0x7f; n>>=7; o+=bytes([b|(0x80 if n else 0)])
        if not n: return o
def s_(x): x=x.encode(); return vi(len(x))+x
def arr(x): return vi(len(x))+x
def pkt(d): return vi(len(d))+d
def bvi(b):
    n=sh=0
    while True:
        x=b.read(1)[0]; n|=(x&0x7f)<<sh; sh+=7
        if not x&0x80: return n
class R:
    def __init__(s,sock): s.sock=sock; s.dec=None
    def byte(s):
        b=s.sock.recv(1)
        if not b: raise EOFError("connection closed")
        return s.dec.update(b) if s.dec else b
    def vi(s):
        n=sh=0
        while True:
            x=s.byte()[0]; n|=(x&0x7f)<<sh; sh+=7
            if not x&0x80: return n
    def packet(s):
        ln=s.vi(); return io.BytesIO(b''.join(s.byte() for _ in range(ln)))
def run(proto, mode, src):
    chat=rsa.generate_private_key(public_exponent=65537,key_size=1024)
    other=rsa.generate_private_key(public_exponent=65537,key_size=1024)
    pubder=chat.public_key().public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)
    s=socket.socket(); s.settimeout(15); s.bind((src,0)); s.connect(("127.0.0.1",25565)); r=R(s)
    s.send(pkt(vi(0)+vi(proto)+s_("localhost")+struct.pack('>H',25565)+vi(2)))
    if mode=="nokey": sigdata=b'\x00'
    else: sigdata=b'\x01'+struct.pack('>q',int(time.time()*1000)+3600000)+arr(pubder)+arr(os.urandom(512))
    uuidpart = b'\x00' if proto==760 else b''
    s.send(pkt(vi(0)+s_("ProbeTest")+sigdata+uuidpart))
    p=r.packet(); bvi(p); p.read(bvi(p)); pub=p.read(bvi(p)); tok=p.read(bvi(p))
    key=load_der_public_key(pub); secret=os.urandom(16); enc=lambda d: key.encrypt(d,padding.PKCS1v15())
    salt=struct.unpack('>q',os.urandom(8))[0]
    signer = other if mode=="wrongkey" else chat
    signed = tok if mode!="wrongtoken" else b'\x00\x00\x00\x00'
    sig=signer.sign(signed+struct.pack('>q',salt),padding.PKCS1v15(),hashes.SHA256())
    s.send(pkt(vi(1)+arr(enc(secret))+b'\x00'+struct.pack('>q',salt)+arr(sig)))
    try:
        p=r.packet(); bvi(p); raw=p.read(bvi(p))
        try: return "kicked (plain): "+json.loads(raw)["text"]
        except Exception: pass
    except EOFError as e: return "closed"
    return "?"
i=60
for proto,name in ((759,"1.19"),(760,"1.19.2")):
    for mode in ("signed","wrongkey","wrongtoken","nokey"):
        i+=1
        # kick before encryption is plain; after Mojang check it's encrypted (reported as '?')
        print(f"{name:6} {mode:10}: {run(proto,mode,'127.0.0.%d'%i)}")
