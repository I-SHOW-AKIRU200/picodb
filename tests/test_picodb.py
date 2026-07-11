#!/usr/bin/env python3
"""PicoDB integration tests. Assumes a server is running on :7120/:7121.
Set PICODB_TOKEN in the environment if the server enforces auth."""
import socket, struct, time, os, json, sys, base64, hashlib, urllib.request, urllib.error

TOKEN = os.environ.get("PICODB_TOKEN", "")
ENG = ("127.0.0.1", 7120)
fails = []

def bf(a, k=b"", v=b"", t=0): return struct.pack(">BHII", a, len(k), len(v), t) + k + v
def bc(): s = socket.create_connection(ENG); s.settimeout(4); return s
def brq(s, a, k=b"", v=b"", t=0): s.sendall(bf(a, k, v, t)); return s.recv(65536)
def recvn(s, n):
    b = b""
    while len(b) < n:
        x = s.recv(n - len(b))
        if not x: break
        b += x
    return b
def bget(s, k):
    """GET returning the value bytes, or None if missing (length-prefixed reply)."""
    s.sendall(bf(GET, k))
    st = recvn(s, 1)
    if st == MISS: return None
    assert st == OK, f"unexpected status {st!r}"
    (ln,) = struct.unpack(">I", recvn(s, 4))
    return recvn(s, ln)
def ck(n, c, g=None):
    print(("PASS " if c else "FAIL ") + n + ("" if c else f"  got={g!r}"))
    if not c: fails.append(n)

SET, GET, DEL, FLUSH, SUB, PUB, AUTH = 1, 2, 3, 4, 5, 6, 7
OK, MISS, A = b"\x00", b"\x44", b"\x41"

def authed_conn():
    s = bc()
    if TOKEN:
        assert brq(s, AUTH, TOKEN.encode()) == OK, "AUTH failed"
    return s

# ---- core ops ----
s = authed_conn()
ck("SET/GET", brq(s, SET, b"foo", b"bar") == OK and bget(s, b"foo") == b"bar")
ck("GET missing", bget(s, b"nope") is None)
ck("DEL", brq(s, DEL, b"foo") == OK and bget(s, b"foo") is None)
ck("binary-safe", brq(s, SET, bytes([0,1,255]), bytes(range(256))) == OK and
   bget(s, bytes([0,1,255])) == bytes(range(256)))
# TTL
brq(s, SET, b"t", b"z", 1); time.sleep(1.2); ck("TTL lazy expiry", bget(s, b"t") is None)
# FLUSH
brq(s, SET, b"a", b"1"); ck("FLUSH", brq(s, FLUSH) == OK and bget(s, b"a") is None)
# pipelined ordering (GET replies are [0x00][len4][value])
s.sendall(bf(SET,b"p1",b"A")+bf(SET,b"p2",b"B")+bf(GET,b"p1")+bf(GET,b"p2"))
time.sleep(0.1)
exp = OK + OK + OK + struct.pack(">I",1) + b"A" + OK + struct.pack(">I",1) + b"B"
ck("pipelined order", recvn(s, len(exp)) == exp)
# 1MB roundtrip
val = bytes([i % 256 for i in range(1_000_000)])
s.sendall(bf(SET, b"big", val)); assert s.recv(1) == OK
ck("1MB roundtrip", bget(s, b"big") == val)
s.close()

# ---- pub/sub ----
authed_conn().sendall(bf(FLUSH))
sub = authed_conn(); sub.sendall(bf(SUB, b"ch")); ck("SUBSCRIBE ack", sub.recv(1) == OK)
time.sleep(0.2)
pub = authed_conn(); brq(pub, PUB, b"ch", b"hi")
time.sleep(0.2)
ck("pub/sub delivery", sub.recv(65536) == b"\x00" + struct.pack(">I", 2) + b"hi")
sub.close(); pub.close()

# ---- HTTP ----
def http(p):
    req = urllib.request.Request(f"http://127.0.0.1:7121{p}")
    if TOKEN: req.add_header("Authorization", "Bearer " + TOKEN)
    try:
        r = urllib.request.urlopen(req, timeout=3); return r.status, r.read().decode("utf-8","replace")
    except urllib.error.HTTPError as e: return e.code, ""
ck("/ 200", http("/")[0] == 200)
ck("/metrics", http("/metrics")[0] == 200 and "picodb_hits_total" in http("/metrics")[1])
st, body = http("/api/keys")
ck("/api/keys json", st == 200 and "keys" in json.loads(body))

# ---- WebSocket handshake + live stats ----
def ws_open():
    s = socket.create_connection(("127.0.0.1", 7121)); s.settimeout(5)
    key = base64.b64encode(os.urandom(16)).decode()
    path = "/ws" + (f"?token={TOKEN}" if TOKEN else "")
    s.sendall((f"GET {path} HTTP/1.1\r\nHost:x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf: buf += s.recv(1024)
    accept = base64.b64encode(hashlib.sha1((key+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
    head = buf.split(b"\r\n\r\n")[0].decode()
    return s, ("101" in head.split("\r\n")[0]) and (f"sec-websocket-accept: {accept}".lower() in head.lower())
def ws_recv(s):
    def rn(n):
        d=b""
        while len(d)<n: d+=s.recv(n-len(d))
        return d
    h=rn(2); op=h[0]&0x0f; l=h[1]&0x7f
    if l==126: l=struct.unpack(">H",rn(2))[0]
    elif l==127: l=struct.unpack(">Q",rn(8))[0]
    return op, (rn(l) if l else b"")
ws, ok = ws_open()
ck("WS handshake+accept", ok)
op, pl = ws_recv(ws)
ck("WS live stats push", op == 0x1 and "hits" in json.loads(pl.decode()))
ws.close()

print("\n" + ("ALL PASSED" if not fails else f"{len(fails)} FAILURES: {fails}"))
sys.exit(1 if fails else 0)
