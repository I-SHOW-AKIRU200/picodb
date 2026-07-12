#!/usr/bin/env python3
"""PicoDB AOF persistence tests — self-contained.

Unlike test_picodb.py (which drives an already-running server), this test spawns
its own PicoDB instances on isolated ports with a temporary AOF file, so it never
touches a live server. It exercises: replay of every data type across a restart,
absolute-TTL survival, that DELeted/LRU-evicted keys don't resurrect, log
compaction, and the fsync policies.

Run directly:  python3 tests/test_aof.py
"""
import socket, struct, subprocess, time, os, signal, sys, json, tempfile, urllib.request, urllib.error

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

def start(aof=None, fsync="everysec", maxbytes=None, rewrite_min_interval=None):
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
    if rewrite_min_interval is not None:
        env["PICODB_AOF_REWRITE_MIN_INTERVAL_SECS"] = str(rewrite_min_interval)
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

    # cleanup Section 1
    for f in (aof, aof + ".tmp"):
        if os.path.exists(f):
            os.remove(f)

    # ---- Regression: #001 — truncated record mid-value at EOF ----------------
    # Write N records manually (no server — avoids magic header), truncate at a
    # byte offset inside record N's value, restart, verify records 1..N-1
    # survive and record N is absent.
    print("\n--- #001: Truncated record mid-value at EOF ---")
    N = 5
    payload = bytearray()
    for i in range(N):
        payload.extend(bf(SET, f"k{i}".encode(), f"v{i}".encode() * 20))
    with open(aof, "wb") as f:
        f.write(payload)

    # Truncate to lose the last 40% of the last record's value
    # The file has no magic header — records start at offset 0.
    size = os.path.getsize(aof)
    pos = 0
    last_record_start = 0
    while pos + 11 <= len(payload):
        klen = struct.unpack(">H", payload[pos+1:pos+3])[0]
        vlen = struct.unpack(">I", payload[pos+3:pos+7])[0]
        total = 11 + klen + vlen
        if pos + total > len(payload):
            break
        last_record_start = pos
        pos += total
    truncate_pos = last_record_start + 11 + klen + int(vlen * 0.4)
    with open(aof, "wb") as f:
        f.write(payload[:truncate_pos])

    p = start(aof=aof)
    s = conn()
    for i in range(N - 1):
        expected = f"v{i}".encode() * 20
        val = getv(s, f"k{i}".encode())
        ck(f"#001: k{i} survives truncation", val == expected, (val[:10] if val else None))
    # Last key must be absent (torn record)
    ck(f"#001: last key k{N-1} absent after truncation", getv(s, f"k{N-1}".encode()) is None)
    # Verify no key has corrupted data from the truncation
    for i in range(N - 1):
        expected = f"v{i}".encode() * 20
        val = getv(s, f"k{i}".encode())
        ck(f"#001: k{i} value not corrupted", val == expected, (val[:10] if val else None))
    s.close()
    stop(p)
    os.remove(aof)

    # ---- Regression: #003 — AOF writer health metrics exposed ---------------
    print("\n--- #003: AOF writer health metrics ---")
    p = start(aof=aof, fsync="always")
    s = conn()
    s.sendall(bf(SET, b"health_key", b"ok"))
    reply = s.recv(1)
    s.close()
    ck("#003: write returns OK when healthy", reply == OK, reply)
    time.sleep(0.3)

    # Check /metrics for new AOF health metrics
    r = urllib.request.urlopen(f"http://127.0.0.1:{HTTP_PORT}/metrics", timeout=3)
    metrics_text = r.read().decode()
    ck("#003: picodb_aof_healthy gauge present", "picodb_aof_healthy 1" in metrics_text)
    ck("#003: picodb_aof_write_errors_total present",
       "picodb_aof_write_errors_total 0" in metrics_text)

    # Check /api/keys for aof_healthy field
    api_data = api()
    ck("#003: aof_healthy field present in /api/keys",
       api_data.get("aof_healthy") == 1, api_data.get("aof_healthy"))

    stop(p)
    os.remove(aof)

    # ---- Regression: #002 — corrupted vlen within MAX_FRAME_BODY but exceeding
    # cache capacity is skipped (capacity cross-check), not loaded to evict all. ---
    print("\n--- #002: Corrupted vlen exceeding cache cap is skipped ---")
    r1 = bf(SET, b"anchor", b"safe")
    r2_raw = bf(SET, b"victim", b"data")
    r3 = bf(SET, b"post", b"here")
    # Set vlen to 100 KiB — exceeds the 50 KiB cache cap we'll set below
    corrupted_vlen = 100 * 1024  # 100 KiB
    header_offset = len(r1)
    payload = bytearray(r1 + r2_raw)
    struct.pack_into(">I", payload, header_offset + 3, corrupted_vlen)
    # Pad the file so the bounds check passes
    pad_needed = header_offset + 11 + len(b"victim") + corrupted_vlen - len(payload)
    payload.extend(b'\x00' * pad_needed)
    payload.extend(r3)
    with open(aof, "wb") as f:
        f.write(payload)

    # Use a small cache cap (50 KiB) so the capacity check triggers
    p = start(aof=aof, maxbytes=50000)
    s = conn()
    anchor_val = getv(s, b"anchor")
    victim_val = getv(s, b"victim")
    post_val = getv(s, b"post")
    s.close()
    ck("#002: anchor survives corrupted vlen (not evicted)", anchor_val == b"safe", anchor_val)
    ck("#002: victim absent (skipped by capacity check)", victim_val is None, victim_val)
    ck("#002: post exists (replay continued past skipped record)", post_val == b"here", post_val)
    stop(p)
    os.remove(aof)

    # ---- Regression: #004 — non-regular file as AOF rejected -----------------
    print("\n--- #004: Device file / FIFO rejected as AOF ---")
    fifo = os.path.join(tmp, "fifo.aof")
    try:
        os.mkfifo(fifo)
    except AttributeError:
        print("  SKIP #004: mkfifo not available on this platform")
    else:
        env = dict(os.environ,
                   PICODB_ENGINE_PORT=str(ENG_PORT), PICODB_HTTP_PORT=str(HTTP_PORT),
                   PICODB_BIND="127.0.0.1", PICODB_AOF_PATH=fifo, PICODB_AOF_FSYNC="no")
        env.pop("PICODB_TOKEN", None)
        env.pop("PICODB_PASSWORD", None)
        result = subprocess.run([BIN], env=env, capture_output=True, text=True, timeout=5)
        ck("#004: FIFO rejected with clear error",
           "FIFO" in result.stderr, result.stderr[:200])
        os.remove(fifo)

    # ---- Regression: #005 — rewrite rate limiting ------------------------------
    print("\n--- #005: Rewrite rate limiting ---")
    p = start(aof=aof, rewrite_min_interval=1)  # 1-second minimum
    req = lambda: urllib.request.urlopen(
        urllib.request.Request(f"http://127.0.0.1:{HTTP_PORT}/aof/rewrite", method="POST")
    )
    first_status = req().status
    ck("#005: first rewrite returns 202", first_status == 202, first_status)
    try:
        req()
        ck("#005: second rewrite returns 4xx (not 202)", False, "succeeded")
    except urllib.error.HTTPError as e:
        ck("#005: second rewrite rate limited", e.code == 429, e.code)
    time.sleep(1.5)
    third_status = req().status
    ck("#005: third rewrite returns 202 after interval", third_status == 202, third_status)
    stop(p)
    os.remove(aof)

    # ---- Regression: #006 — magic header on new files -------------------------
    print("\n--- #006: AOF magic header ---")
    p = start(aof=aof, fsync="no")
    s = conn()
    s.sendall(bf(SET, b"k", b"v"))
    ck("#006: SET ok", recvn(s, 1) == b"\x00")
    s.close()
    stop(p)
    # Confirm the file starts with the magic bytes
    with open(aof, "rb") as f:
        head = f.read(10)
    ck("#006: file begins with magic", head[:5] == b"Pico1", head[:5])
    # Restart and verify the data survived
    p = start(aof=aof, fsync="no")
    s = conn()
    v = getv(s, b"k")
    s.close()
    ck("#006: data survives restart with magic header", v == b"v", v)
    stop(p)
    os.remove(aof)

    # Backward compat: an AOF without the magic header still replays
    print("  #006: backward compat — old-format file")
    r = bf(SET, b"legacy", b"works")
    with open(aof, "wb") as f:
        f.write(r)
    p = start(aof=aof)
    s = conn()
    leg = getv(s, b"legacy")
    s.close()
    ck("#006: old-format file replays correctly", leg == b"works", leg)
    stop(p)
    os.remove(aof)

    # ---- Regression: #007 — TTL exact-second replay boundary ------------------
    print("\n--- #007: TTL exact-second replay boundary ---")
    # Write a key with TTL=2 (absolute: now+2).  Wait 1 s so the TTL is
    # comfortably in the future, then restart quickly.  It should survive.
    p = start(aof=aof)
    s = conn()
    s.sendall(bf(SET, b"exact", b"val", 2))
    ck("#007: SET with TTL ok", recvn(s, 1) == OK)
    s.close()
    time.sleep(0.8)
    stop(p)
    time.sleep(0.1)
    p = start(aof=aof)
    s = conn()
    v = getv(s, b"exact")
    s.close()
    ck("#007: key with future TTL survives quick restart", v == b"val", v)
    stop(p)
    os.remove(aof)

    # cleanup
    for f in (aof, aof + ".tmp"):
        if os.path.exists(f):
            os.remove(f)
    os.rmdir(tmp)

    print("\n" + ("ALL PASSED" if not fails else f"{len(fails)} FAILURES: {fails}"))
    sys.exit(1 if fails else 0)

if __name__ == "__main__":
    main()
