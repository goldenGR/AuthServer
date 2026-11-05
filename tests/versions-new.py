import socket, struct, io, os, sys, json, uuid
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
def vi(n):
    o=b''
    while True:
        b=n&0x7f; n>>=7; o+=bytes([b|(0x80 if n else 0)])
        if not n: return o
def s_(x): x=x.encode(); return vi(len(x))+x
def pkt(d): return vi(len(d))+d
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
def bvi(b):
    n=sh=0
    while True:
        x=b.read(1)[0]; n|=(x&0x7f)<<sh; sh+=7
        if not x&0x80: return n
def conn(src):
    s=socket.socket(); s.settimeout(15); s.bind((src,0)); s.connect(("127.0.0.1",25565)); return s
def ping(proto, src):
    s=conn(src); r=R(s)
    s.send(pkt(vi(0)+vi(proto)+s_("localhost")+struct.pack('>H',25565)+vi(1))); s.send(pkt(vi(0)))
    p=r.packet(); bvi(p); j=json.loads(p.read(bvi(p))); s.close()
    return j["version"]["protocol"]
def login(proto, src):
    s=conn(src); r=R(s); short = proto < 47
    arr = (lambda x: struct.pack('>h',len(x))+x) if short else (lambda x: vi(len(x))+x)
    s.send(pkt(vi(0)+vi(proto)+s_("localhost")+struct.pack('>H',25565)+vi(2)))
    name=s_("ProbeTest")
    if proto in (759,):        body=name+b'\x00'
    elif proto==760:           body=name+b'\x00\x00'
    elif 761<=proto<=763:      body=name+b'\x01'+uuid.uuid4().bytes
    elif proto>=764:           body=name+uuid.uuid4().bytes
    else:                      body=name
    s.send(pkt(vi(0)+body))
    p=r.packet(); pid=bvi(p)
    if pid!=1: return "unexpected packet %d: %r" % (pid, p.read()[:80])
    p.read(bvi(p))
    rd=(lambda: p.read(struct.unpack('>h',p.read(2))[0])) if short else (lambda: p.read(bvi(p)))
    pub=rd(); tok=rd()
    key=load_der_public_key(pub); secret=os.urandom(16); enc=lambda d: key.encrypt(d,padding.PKCS1v15())
    mid = b'\x01' if proto in (759,760) else b''
    s.send(pkt(vi(1)+arr(enc(secret))+mid+arr(enc(tok))))
    r.dec=Cipher(algorithms.AES(secret),modes.CFB8(secret)).decryptor()
    p=r.packet(); pid=bvi(p); msg=json.loads(p.read(bvi(p)).decode())
    return "kicked: " + (msg.get("text") if isinstance(msg,dict) else str(msg))
V=[("1.7.10",5),("1.8.9",47),("1.12.2",340),("1.16.5",754),("1.18.2",758),("1.19",759),("1.19.2",760),("1.19.4",762),("1.20.4",765),("1.21",767),("1.21.11",774),("26.1",775),("26.3",777)]
for i,(name,proto) in enumerate(V):
    src="127.0.0.%d"%(100+i)
    try: pr=ping(proto,src); pres="ping ok"
    except Exception as e: pres="ping FAIL %r"%e
    try: lres=login(proto,src)
    except Exception as e: lres="login FAIL %r"%e
    print(f"{name:8} (proto {proto:3}): {pres:8} | {lres}")
