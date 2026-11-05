import socket, time, os, struct
def vi(n):
    o=b''
    while True:
        b=n&0x7f; n>>=7; o+=bytes([b|(0x80 if n else 0)])
        if not n: return o
def pkt(d): return vi(len(d))+d
def c(src):
    s=socket.socket(); s.settimeout(5); s.bind((src,0)); s.connect(("127.0.0.1",25565)); return s
def alive(s):
    s.settimeout(0.5)
    try:
        d=s.recv(1); return "closed" if d==b'' else "got data"
    except socket.timeout: return "open"
    except OSError as e: return "closed (%s)"%e.__class__.__name__
print("## 1) 4 idle connections from one IP (limit is 3)")
socks=[c("127.0.0.50") for _ in range(4)]; time.sleep(1)
print("   ", [alive(s) for s in socks])
print("## 2) garbage data, then a normal ping still works?")
g=c("127.0.0.51"); g.send(os.urandom(200)); time.sleep(1); print("    garbage conn:", alive(g))
g=c("127.0.0.52"); g.send(b'\xff\xff\xff\xff\xff\xff'); time.sleep(1); print("    bad length conn:", alive(g))
p=c("127.0.0.53"); h=b'localhost'
p.send(pkt(vi(0)+vi(767)+vi(len(h))+h+struct.pack('>H',25565)+vi(1))+pkt(vi(0)))
time.sleep(0.5); print("    ping after garbage:", "ok" if p.recv(5) else "fail")
print("## 3) idle connection timeout: checking socks[0] every 10s for 40s")
for t in (10,20,30,40):
    time.sleep(10); print("    after %ds:"%t, alive(socks[0]))
