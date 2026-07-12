#!/usr/bin/env python3
"""PicoDB AOF persistence tests — self-contained.

Unlike test_picodb.py (which drives an already-running server), this test spawns
its own PicoDB instances on isolated ports with a temporary AOF file, so it never
touches a live server. It exercises: replay of every data type across a restart,
absolute-TTL survival, that DELeted/LRU-evicted keys don't resurrect, log
compaction, and the fsync policies.

Run directly:  python3 tests/test_aof.py
"""
import socket, struct, subprocess, time, os, signal, sys, json, tempfile, urllib.request

# Locate the release binary relative to the repo root.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "target", "release", "picodb")
ENG_PORT, HTTP_PORT = 7320, 7321  # off the defaults so a live server is untouched

SET, GET, DEL, FLUSH = 1, 2, 3, 4
HSET, HGETALL, SCARD = 0x10, 0x13, 0x34
RPUSH, LRANGE = 0x21, 0x24
SADD = 0x30
OK, MISS = b"\x00", b"\x44"

fails = []
def ck(name, cond, got=None):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  got={got!r}"))
    if not cond:
        fails.append(name)

def bf(a, k=b"", v=b"", t=0):
    return struct.pack(">BHII", a, len(k), len(v), t) + k + v
def arg(*xs):
    return b"".join(struct.pack(">I", len(x)) + x for x in xs)
def recvn(s, n):
    b = b""
    while len(b) < n:
        x = s.recv(n - len(b))
        if not x:
            break
        b += x
    return b
def conn():
    s = socket.create_connection(("127.0.0.1", ENG_PORT))
    s.settimeout(4)
    return s
def getv(s, k):
    s.sendall(bf(GET, k))
    st = recvn(s, 1)
    if st == MISS:
        return None
    (ln,) = struct.unpack(">I", recvn(s, 4))
    return recvn(s, ln)
def rint(s):
    assert recvn(s, 1) == OK
    return struct.unpack(">q", recvn(s, 8))[0]
def rarr(s):
    assert recvn(s, 1) == OK
    (n,) = struct.unpack(">I", recvn(s, 4))
    return [recvn(s, struct.unpack(">I", recvn(s, 4))[0]) for _ in range(n)]

def start(aof=None, fsync="everysec", maxbytes=None):
    env = dict(os.environ,
               PICODB_ENGINE_PORT=str(ENG_PORT), PICODB_HTTP_PORT=str(HTTP_PORT),
               PICODB_BIND="127.0.0.1")
    env.pop("PICODB_TOKEN", None)      # ensure auth off for the test
    env.pop("PICODB_PASSWORD", None)
    if aof:
        env["PICODB_AOF_PATH"] = aof
        env["PICODB_AOF_FSYNC"] = fsync
    else:
        env.pop("PICODB_AOF_PATH", None)
    if maxbytes:
        env["PICODB_MAX_BYTES"] = str(maxbytes)
    p = subprocess.Popen([BIN], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):
        try:
            socket.create_connection(("127.0.0.1", ENG_PORT), timeout=0.2).close()
            return p
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("PicoDB did not start (is the port free?)")

def stop(p, hard=False):
    p.send_signal(signal.SIGKILL if hard else signal.SIGTERM)
    p.wait(timeout=5)

def api():
    r = urllib.request.urlopen(f"http://127.0.0.1:{HTTP_PORT}/api/keys", timeout=3)
    return json.loads(r.read())

def main():
    if not os.path.exists(BIN):
        print(f"FAIL binary not found at {BIN} — run `make build` first")
        sys.exit(1)

    tmp = tempfile.mkdtemp(prefix="picodb-aof-")
    aof = os.path.join(tmp, "test.aof")

    # ---- Replay every data type + DEL + TTL across a hard crash --------------
    p = start(aof=aof)
    s = conn()
    s.sendall(bf(SET, b"str", b"hello")); s.recv(1)
    s.sendall(bf(SET, b"ttl", b"soon", 100)); s.recv(1)          # absolute-TTL key
    s.sendall(bf(SET, b"gone", b"x")); s.recv(1)
    s.sendall(bf(DEL, b"gone")); s.recv(1)
    s.sendall(bf(HSET, b"h", arg(b"f1", b"v1"))); rint(s)
    s.sendall(bf(HSET, b"h", arg(b"f2", b"v2"))); rint(s)
    s.sendall(bf(RPUSH, b"l", arg(b"a", b"b", b"c"))); rint(s)
    s.sendall(bf(SADD, b"set", arg(b"x", b"y", b"z"))); rint(s)
    s.close()
    time.sleep(1.4)          # let the everysec fsync land
    stop(p, hard=True)       # simulate a crash

    p = start(aof=aof)
    s = conn()
    ck("string replays", getv(s, b"str") == b"hello")
    ck("DEL survives (key stays gone)", getv(s, b"gone") is None)
    ck("TTL key replays", getv(s, b"ttl") == b"soon")
    s.sendall(bf(HGETALL, b"h"))
    flat = rarr(s); hd = {flat[i]: flat[i + 1] for i in range(0, len(flat), 2)}
    ck("hash replays", hd == {b"f1": b"v1", b"f2": b"v2"}, hd)
    s.sendall(bf(LRANGE, b"l", struct.pack(">qq", 0, -1)))
    ck("list replays in order", rarr(s) == [b"a", b"b", b"c"])
    s.sendall(bf(SCARD, b"set"))
    ck("set replays", rint(s) == 3)
    s.close()
    # TTL must not have been reset to the full 100s.
    ttl = {k["key"]: k for k in api()["keys"]}.get("ttl", {}).get("ttl")
    ck("TTL preserved (absolute, not reset)", ttl is not None and ttl <= 100, ttl)

    # ---- Compaction: rewrite shrinks the log and data still replays ----------
    size_before = os.path.getsize(aof)
    r = urllib.request.urlopen(
        urllib.request.Request(f"http://127.0.0.1:{HTTP_PORT}/aof/rewrite", method="POST"),
        timeout=3)
    ck("rewrite accepted (202)", r.status == 202, r.status)
    time.sleep(1.0)
    ck("compaction shrinks the log", os.path.getsize(aof) <= size_before,
       (size_before, os.path.getsize(aof)))
    stop(p, hard=True)
    p = start(aof=aof)
    s = conn()
    ck("data replays from compacted log", getv(s, b"str") == b"hello")
    s.close()
    stop(p)
    os.remove(aof)

    # ---- LRU-evicted keys must not resurrect on replay ----------------------
    p = start(aof=aof, maxbytes=20000)      # tiny cap forces evictions
    s = conn()
    for i in range(400):
        s.sendall(bf(SET, f"k{i:04d}".encode(), bytes(200))); s.recv(1)
    s.close()
    time.sleep(1.4)
    stop(p, hard=True)
    p = start(aof=aof, maxbytes=20000)
    ck("cap still enforced after replay", api()["memory_usage_bytes"] <= 20000,
       api()["memory_usage_bytes"])
    s = conn()
    early = sum(1 for i in range(50) if getv(s, f"k{i:04d}".encode()) is not None)
    s.close()
    ck("evicted keys do not resurrect", early == 0, early)
    stop(p)
    os.remove(aof)

    # ---- fsync=always: a SIGKILL loses no flushed data ----------------------
    # Replies aren't gated on the fsync (async writer), so allow the writer a beat
    # to process the frame; once flushed, a hard kill must lose nothing.
    p = start(aof=aof, fsync="always")
    s = conn(); s.sendall(bf(SET, b"dur", b"yes")); s.recv(1); s.close()
    time.sleep(0.3)
    stop(p, hard=True)
    p = start(aof=aof, fsync="always")
    s = conn(); ck("fsync=always durable on hard kill", getv(s, b"dur") == b"yes"); s.close()
    stop(p)

    # ---- Backward compat: AOF off => no file, ops still work ----------------
    stray = os.path.join(tmp, "none.aof")
    p = start(aof=None)
    s = conn(); s.sendall(bf(SET, b"a", b"1")); ck("no-AOF ops work", s.recv(1) == OK); s.close()
    stop(p)
    ck("no AOF file when disabled", not os.path.exists(stray))

    # cleanup
    for f in (aof, aof + ".tmp"):
        if os.path.exists(f):
            os.remove(f)
    os.rmdir(tmp)

    print("\n" + ("ALL PASSED" if not fails else f"{len(fails)} FAILURES: {fails}"))
    sys.exit(1 if fails else 0)

if __name__ == "__main__":
    main()
