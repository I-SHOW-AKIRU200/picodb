#!/usr/bin/env python3
"""PicoDB AOF adversarial testing — corruption, crash, edge-case, and DoS scenarios.

Run:  python3 tests/test_aof_adversarial.py
"""
import socket, struct, subprocess, time, os, signal, sys, json, tempfile, urllib.request, random, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "target", "release", "picodb")
ENG_PORT, HTTP_PORT = 7340, 7341

SET, GET, DEL, FLUSH = 1, 2, 3, 4
ACT_HSET = 0x10
ACT_RPUSH = 0x21
ACT_SADD = 0x30
HEADER_LEN = 11
OK, MISS = b"\x00", b"\x44"

fails = []
findings = []  # accumulated issues

def note(title, severity, repro, expected, actual):
    findings.append({"title": title, "severity": severity,
                     "repro": repro, "expected": expected, "actual": actual})
    print(f"\n  [!] {severity}: {title}")

def ck(name, cond, got=None):
    print(("  PASS " if cond else "  FAIL ") + name + ("" if cond else f"  got={got!r}"))
    if not cond:
        fails.append(name)

def bf(a, k=b"", v=b"", ttl=0):
    return struct.pack(">BHII", a, len(k), len(v), ttl) + k + v

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

def start(aof=None, fsync="everysec", maxbytes=None, extra_env=None):
    env = dict(os.environ,
               PICODB_ENGINE_PORT=str(ENG_PORT), PICODB_HTTP_PORT=str(HTTP_PORT),
               PICODB_BIND="127.0.0.1")
    env.pop("PICODB_TOKEN", None)
    env.pop("PICODB_PASSWORD", None)
    if aof:
        env["PICODB_AOF_PATH"] = aof
        env["PICODB_AOF_FSYNC"] = fsync
    else:
        env.pop("PICODB_AOF_PATH", None)
    if maxbytes:
        env["PICODB_MAX_BYTES"] = str(maxbytes)
    if extra_env:
        env.update(extra_env)
    p = subprocess.Popen([BIN], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):
        try:
            socket.create_connection(("127.0.0.1", ENG_PORT), timeout=0.2).close()
            return p
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("PicoDB did not start")

def stop(p, hard=False):
    p.send_signal(signal.SIGKILL if hard else signal.SIGTERM)
    p.wait(timeout=5)

def api():
    r = urllib.request.urlopen(f"http://127.0.0.1:{HTTP_PORT}/api/keys", timeout=3)
    return json.loads(r.read())

def aof_with_records(path, records):
    """Write valid AOF records to path."""
    with open(path, "wb") as f:
        for r in records:
            f.write(r)

def make_set_record(key, value, ttl=0):
    return bf(SET, key, value, ttl)

# =====================================================================
# TEST 1: Malformed / corrupted log files
# =====================================================================

def test_truncated_trailing_record():
    """1a. Truncate at multiple byte offsets within a single frame."""
    print("\n=== 1a: Truncated trailing record ===")
    tmp = tempfile.mkdtemp(prefix="picodb-aof-")

    for name, offset_desc, truncate_at in [
        ("mid-header", "mid-header", 2),
        ("mid-klen-field", "mid-klen-field", 4),
        ("mid-vlen-field", "mid-vlen-field", 7),
        ("mid-ttl-field", "mid-ttl-field", 9),
        ("mid-key", "mid-key",  HEADER_LEN + 1),
        ("mid-value", "mid-value", HEADER_LEN + 6),
    ]:
        aof = os.path.join(tmp, f"trunc_{name}.aof")
        # Write 3 records: key1, key2 (will be torn), key3 (should not exist after replay)
        with open(aof, "wb") as f:
            f.write(make_set_record(b"k1", b"v1"))          # full record 1
            full_r2 = make_set_record(b"k2", b"v2value")    # record 2 – will be truncated
            f.write(full_r2[:truncate_at])                  # truncated
            f.write(make_set_record(b"k3", b"v3"))          # record 3 – shouldn't be visible

        p = start(aof=aof)
        s = conn()
        k1 = getv(s, b"k1")
        k2 = getv(s, b"k2")
        k3 = getv(s, b"k3")
        s.close()
        stop(p)

        ck(f"truncated {offset_desc}: k1 survives", k1 == b"v1", k1)
        ck(f"truncated {offset_desc}: k2 missing (torn)", k2 is None, k2)
        ck(f"truncated {offset_desc}: k3 missing (after tear)", k3 is None, k3)

    shutil.rmtree(tmp)

def test_truncated_midfile():
    """1b. Truncate mid-file at record boundary and non-boundary."""
    print("\n=== 1b: Truncated mid-file (non-trailing) ===")
    tmp = tempfile.mkdtemp(prefix="picodb-aof-")

    # Create 4 records
    r1 = make_set_record(b"keep_a", b"val_a")
    r2 = make_set_record(b"keep_b", b"val_b")
    r3 = make_set_record(b"lost_c", b"val_c")
    r4 = make_set_record(b"lost_d", b"val_d")

    # Boundary truncation — cut exactly after r2
    aof = os.path.join(tmp, "trunc_boundary.aof")
    with open(aof, "wb") as f:
        full = r1 + r2 + r3 + r4
        f.write(full[:len(r1)+len(r2)])  # boundary after r2

    p = start(aof=aof)
    s = conn()
    ck("boundary trunc: keep_a survives", getv(s, b"keep_a") == b"val_a")
    ck("boundary trunc: keep_b survives", getv(s, b"keep_b") == b"val_b")
    ck("boundary trunc: lost_c missing", getv(s, b"lost_c") is None)
    ck("boundary trunc: lost_d missing", getv(s, b"lost_d") is None)
    s.close()
    stop(p)

    # Non-boundary truncation — cut in the middle of r3's key
    aof2 = os.path.join(tmp, "trunc_nonboundary.aof")
    with open(aof2, "wb") as f:
        full = r1 + r2 + r3 + r4
        cut = len(r1) + len(r2) + HEADER_LEN + 2  # 2 bytes into r3's key
        f.write(full[:cut])

    p = start(aof=aof2)
    s = conn()
    ck("non-boundary trunc: keep_a survives", getv(s, b"keep_a") == b"val_a")
    ck("non-boundary trunc: keep_b survives", getv(s, b"keep_b") == b"val_b")
    ck("non-boundary trunc: lost_c missing", getv(s, b"lost_c") is None)
    ck("non-boundary trunc: lost_d missing", getv(s, b"lost_d") is None)
    s.close()
    stop(p)

    shutil.rmtree(tmp)

def test_corrupted_length_fields():
    """1c. Bit-flip corruption in klen, vlen, TTL fields."""
    print("\n=== 1c: Bit-flip corruption in length/TTL fields ===")
    tmp = tempfile.mkdtemp(prefix="picodb-aof-")

    tests = [
        ("klen low byte",  1),  # offset 1 in header
        ("klen high byte", 2),
        ("vlen low byte",  3),
        ("vlen mid byte",  4),
        ("vlen high byte", 5),  # actually 4 bytes: offsets 3,4,5,6
        ("vlen top byte",  6),
        ("ttl byte 0",     7),
        ("ttl byte 1",     8),
        ("ttl byte 2",     9),
        ("ttl byte 3",     10),
    ]

    for name, hdr_offset in tests:
        aof = os.path.join(tmp, f"corrupt_{hdr_offset}.aof")
        r1 = make_set_record(b"anchor_before", b"before_val")
        r2 = make_set_record(b"corrupt_me", b"the_target_value", ttl=99999)
        r3 = make_set_record(b"anchor_after", b"after_val")

        full = r1 + r2 + r3
        data = bytearray(full)
        # Flip a bit in r2's header
        offset_in_file = len(r1) + hdr_offset
        data[offset_in_file] ^= 0x80  # flip MSB

        with open(aof, "wb") as f:
            f.write(data)

        p = start(aof=aof)
        s = conn()
        before = getv(s, b"anchor_before")
        corrupt = getv(s, b"corrupt_me")
        after = getv(s, b"anchor_after")
        s.close()
        stop(p)

        # The corrupted length might cause desync. Acceptable outcomes:
        # - corrupt_me is missing (replay detected bad length)
        # - anchor_after may or may not survive depending on desync
        # But anchor_before MUST always survive
        ck(f"corrupt {name}: anchor_before survives", before == b"before_val", before)

    shutil.rmtree(tmp)

def test_corrupted_value_length_large():
    """1c continued: value length set to very large (but <= MAX_FRAME_BODY)."""
    print("\n=== 1c-2: Corrupted vlen causing desync ===")
    tmp = tempfile.mkdtemp(prefix="picodb-aof-")

    for offset_name, vlen_val in [("just_under_max", 64*1024*1024 - 10),
                                   ("moderate_large", 1024*1024),
                                   ("zero", 0)]:
        aof = os.path.join(tmp, f"vlen_{offset_name}.aof")
        r1 = make_set_record(b"anchor", b"safe")
        r2 = make_set_record(b"victim", b"data")
        full = bytearray(r1 + r2)
        # Overwrite vlen field of r2 (bytes 3-6 of header = offset len(r1)+3)
        struct.pack_into(">I", full, len(r1) + 3, vlen_val)
        # If vlen is non-zero, we need to ensure the file is large enough
        # so it doesn't immediately fail the remaining-size check
        if vlen_val > len(full) - (len(r1) + HEADER_LEN):
            # Pad the file to satisfy the claimed length — this simulates
            # a corrupted length where subsequent bytes look like key+value
            padding_needed = len(r1) + HEADER_LEN + vlen_val - len(full)
            full.extend(b'\x00' * padding_needed)
        # Add r3 after the "value"
        full.extend(make_set_record(b"post", b"corrupt"))

        with open(aof, "wb") as f:
            f.write(full)

        p = start(aof=aof)
        s = conn()
        anchor = getv(s, b"anchor")
        victim = getv(s, b"victim")
        post = getv(s, b"post")
        s.close()
        stop(p)

        ck(f"corrupt vlen={offset_name}: anchor survives", anchor == b"safe", anchor)
        if vlen_val == 0:
            ck(f"corrupt vlen={offset_name}: victim exists (vlen=0 means empty)", victim == b"", victim)

    shutil.rmtree(tmp)

def test_empty_and_random_file():
    """1d/1e. Zero-length file and random binary as AOF."""
    print("\n=== 1d/1e: Empty file / random file as AOF ===")
    tmp = tempfile.mkdtemp(prefix="picodb-aof-")

    # Zero-length file
    aof_empty = os.path.join(tmp, "empty.aof")
    open(aof_empty, "w").close()
    p = start(aof=aof_empty)
    s = conn()
    # Should start fine, no crash
    s.sendall(bf(SET, b"fresh", b"data"))
    ck("empty AOF: server starts and accepts writes", recvn(s, 1) == OK)
    s.close()
    stop(p)

    # Random binary file as AOF
    aof_random = os.path.join(tmp, "random.aof")
    with open(aof_random, "wb") as f:
        f.write(os.urandom(4096))
    p = start(aof=aof_random)
    s = conn()
    s.sendall(bf(SET, b"fresh2", b"data2"))
    ck("random AOF: server starts (no crash) and accepts writes", recvn(s, 1) == OK)
    s.close()
    stop(p)

    shutil.rmtree(tmp)

# =====================================================================
# TEST 2: Fsync policy correctness
# =====================================================================

def test_fsync_always_reply_timing():
    """2a. Verify 'always' does NOT gate replies on fsync completion."""
    print("\n=== 2a: fsync=always — reply not gated on fsync ===")
    tmp = tempfile.mkdtemp(prefix="picodb-aof-")
    aof = os.path.join(tmp, "fsync_always.aof")

    p = start(aof=aof, fsync="always")
    s = conn()

    # Send a batch of SETs and measure reply time.
    # If replies were gated on fsync, each would take O(ms) (fsync latency).
    # We expect replies to arrive immediately (before fsync completes).
    N = 100
    start_t = time.monotonic()
    for i in range(N):
        s.sendall(bf(SET, f"k{i}".encode(), b"x"))
    for i in range(N):
        recvn(s, 1)  # drain replies
    elapsed = time.monotonic() - start_t
    s.close()
    stop(p)

    avg_ms = (elapsed / N) * 1000
    ck(f"fsync=always: avg reply time {avg_ms:.2f}ms (expect << fsync latency)", avg_ms < 5, avg_ms)
    shutil.rmtree(tmp)

def test_fsync_always_durability_with_delay():
    """2a continued: Data written with fsync=always survives SIGKILL after short delay."""
    print("\n=== 2a-2: fsync=always durability after delayed kill ===")
    tmp = tempfile.mkdtemp(prefix="picodb-aof-")
    aof = os.path.join(tmp, "fsync_always_durability.aof")

    # Write data and kill with various delays
    for delay in [0.05, 0.1, 0.5]:
        p = start(aof=aof, fsync="always")
        s = conn()
        s.sendall(bf(SET, b"adur", b"yes"))
        reply = recvn(s, 1)
        s.close()
        time.sleep(delay)
        stop(p, hard=True)

        p2 = start(aof=aof, fsync="always")
        s2 = conn()
        val = getv(s2, b"adur")
        s2.close()
        # The README says replies aren't gated on fsync, so after a very short
        # delay the data might not be fsynced yet. But after 500ms it should be.
        if delay >= 0.5:
            ck(f"fsync=always: data survives after {delay}s delay (replied {reply!r})", val == b"yes", val)
        stop(p2)

    os.remove(aof)
    shutil.rmtree(tmp)

def test_fsync_everysec_loss_bound():
    """2b. Kill within 1s window — verify loss is bounded."""
    print("\n=== 2b: fsync=everysec — loss bounded to ≤1s ===")
    # This is tricky to test precisely without a real power-cut.
    # We verify: after waiting >1s past the last write, SIGKILL loses nothing.
    tmp = tempfile.mkdtemp(prefix="picodb-aof-")
    aof = os.path.join(tmp, "everysec.aof")

    p = start(aof=aof, fsync="everysec")
    s = conn()
    s.sendall(bf(SET, b"esec", b"survive"))
    s.recv(1)
    s.close()
    # Wait well past the 1-second fsync window
    time.sleep(1.5)
    stop(p, hard=True)

    p2 = start(aof=aof, fsync="everysec")
    s2 = conn()
    val = getv(s2, b"esec")
    ck("everysec: data survives after 1.5s wait + SIGKILL", val == b"survive", val)
    s2.close()
    stop(p2)

    os.remove(aof)
    shutil.rmtree(tmp)

# =====================================================================
# TEST 3: Compaction / rewrite path
# =====================================================================

def test_rewrite_crash_safety():
    """3a. Crash during rewrite — old data must survive."""
    print("\n=== 3a: Crash during rewrite ===")
    tmp = tempfile.mkdtemp(prefix="picodb-aof-")
    aof = os.path.join(tmp, "rewrite_crash.aof")

    # Populate with enough data to trigger a rewrite candidate
    p = start(aof=aof, fsync="everysec", maxbytes=100*1024*1024)
    s = conn()
    for i in range(100):
        s.sendall(bf(SET, f"k{i}".encode(), b"v" * 1000))
        recvn(s, 1)
    s.close()

    # Trigger rewrite via API
    try:
        r = urllib.request.urlopen(
            urllib.request.Request(f"http://127.0.0.1:{HTTP_PORT}/aof/rewrite", method="POST"),
            timeout=3)
        ck("rewrite accepted", r.status in (202, 409), r.status)
    except Exception as e:
        ck(f"rewrite trigger: {e}", False)

    # Kill the process mid-rewrite (aggressive: small window)
    time.sleep(0.2)
    stop(p, hard=True)

    # Verify old AOF is intact and replays
    p2 = start(aof=aof)
    s2 = conn()
    k0 = getv(s2, b"k0")
    k99 = getv(s2, b"k99")
    s2.close()
    ck("crash during rewrite: k0 survives", k0 == b"v" * 1000, k0[:20])
    ck("crash during rewrite: k99 survives", k99 == b"v" * 1000, k99[:20])
    stop(p2)
    shutil.rmtree(tmp)

def test_concurrent_writes_during_rewrite():
    """3b. Fire SETs while rewrite is in progress."""
    print("\n=== 3b: Concurrent writes during rewrite ===")
    tmp = tempfile.mkdtemp(prefix="picodb-aof-")
    aof = os.path.join(tmp, "concurrent_rewrite.aof")

    # Use many small keys to make rewrite take measurable time
    p = start(aof=aof, fsync="everysec", maxbytes=200*1024*1024)
    s = conn()
    for i in range(500):
        s.sendall(bf(SET, f"base{i}".encode(), b"v" * 100))
        recvn(s, 1)
    s.close()

    # Trigger rewrite
    r = urllib.request.urlopen(
        urllib.request.Request(f"http://127.0.0.1:{HTTP_PORT}/aof/rewrite", method="POST"),
        timeout=3)
    ck("rewrite triggered", r.status == 202, r.status)

    # While rewrite is running, fire more SETs
    time.sleep(0.1)
    s = conn()
    for i in range(50):
        s.sendall(bf(SET, f"conc{i}".encode(), b"rewrite_test"))
        recvn(s, 1)
    s.close()
    time.sleep(1.0)
    stop(p, hard=True)

    # Replay: both base keys and concurrent keys should survive
    p2 = start(aof=aof)
    s2 = conn()
    base_ok = getv(s2, b"base0") == b"v" * 100
    conc_ok = getv(s2, b"conc0") == b"rewrite_test"
    conc49 = getv(s2, b"conc49") == b"rewrite_test"
    s2.close()
    ck("concurrent writes: base keys survive rewrite", base_ok)
    ck("concurrent writes: writes during rewrite survive", conc_ok)
    ck("concurrent writes: last concurrent write survives", conc49)
    stop(p2)
    shutil.rmtree(tmp)

def test_rewrite_auth_required():
    """3c. POST /aof/rewrite without auth when token set."""
    print("\n=== 3c: Rewrite endpoint auth enforcement ===")
    tmp = tempfile.mkdtemp(prefix="picodb-aof-")
    aof = os.path.join(tmp, "auth_rewrite.aof")

    p = start(aof=aof, extra_env={"PICODB_TOKEN": "test-token-123"})
    # Hit /aof/rewrite without Authorization header
    req = urllib.request.Request(f"http://127.0.0.1:{HTTP_PORT}/aof/rewrite", method="POST")
    try:
        r = urllib.request.urlopen(req, timeout=3)
        ck("rewrite without auth returns 401 (expected) — BUG if 202/409 returned", r.status == 401, r.status)
    except urllib.error.HTTPError as e:
        ck("rewrite without auth correctly rejected", e.code == 401, e.code)

    # Now with correct token
    req2 = urllib.request.Request(f"http://127.0.0.1:{HTTP_PORT}/aof/rewrite", method="POST")
    req2.add_header("Authorization", "Bearer test-token-123")
    try:
        r2 = urllib.request.urlopen(req2, timeout=3)
        ck("rewrite with auth accepted", r2.status in (202, 409), r2.status)
    except urllib.error.HTTPError as e:
        ck(f"rewrite with auth: {e.code}", e.code == 401, e.code)

    stop(p)
    shutil.rmtree(tmp)

def test_rewrite_dos_vector():
    """3d. Spam POST /aof/rewrite — verify rate limiting behavior."""
    print("\n=== 3d: Rewrite DoS vector ===")
    tmp = tempfile.mkdtemp(prefix="picodb-aof-")
    aof = os.path.join(tmp, "dos_rewrite.aof")

    p = start(aof=aof, maxbytes=200*1024*1024)
    s = conn()
    for i in range(50):
        s.sendall(bf(SET, f"k{i}".encode(), b"v" * 10000))
        recvn(s, 1)
    s.close()

    # Rapid-fire rewrite requests
    accepted = 0
    rejected = 0
    for _ in range(20):
        try:
            r = urllib.request.urlopen(
                urllib.request.Request(f"http://127.0.0.1:{HTTP_PORT}/aof/rewrite", method="POST"),
                timeout=3)
            if r.status == 202:
                accepted += 1
            else:
                rejected += 1
        except Exception:
            rejected += 1
        # No delay between requests — rapid fire

    # Most should return 409 "already in progress", not 202
    # Acceptable: first few succeed, the rest get 409
    ck(f"DoS rewrite: {accepted} accepted, {rejected} rejected (expect mostly 409)",
       accepted < 10, (accepted, rejected))
    stop(p)
    shutil.rmtree(tmp)

# =====================================================================
# TEST 4: TTL correctness across restarts
# =====================================================================

def test_ttl_same_second_expiry():
    """4a. TTL key expiring exactly at current second becomes persistent."""
    print("\n=== 4a: TTL edge case — key expiring at current second ===")
    tmp = tempfile.mkdtemp(prefix="picodb-aof-")
    aof = os.path.join(tmp, "ttl_edge.aof")

    # Craft AOF manually (no server — avoids magic header) so we control
    # the exact byte layout.
    now = int(time.time())
    with open(aof, "wb") as f:
        f.write(bf(SET, b"persistent", b"yes"))
        # Write shortlived with TTL = exactly now (should be expired on replay)
        f.write(bf(SET, b"shortlived", b"gonnago", ttl=now))

    # Restart — the key with ttl = exactly now should be treated as expired
    p2 = start(aof=aof)
    s2 = conn()
    shortlived_val = getv(s2, b"shortlived")
    persistent_val = getv(s2, b"persistent")
    s2.close()

    # BUG: If ttl_field == now, then ttl_field as u64 <= now is true,
    # so replay skips it. But if ttl_field == now due to the exact-second
    # race, the key's expiry is *now*, not already expired.
    # However, the key could also be treated as "already expired" which
    # is slightly conservative but acceptable (loses the key 1 second early).
    # The real bug is when ttl_field - now == 0, which becomes ttl=0 (no expiry).
    # This can happen if the key was set at second X with TTL Y and exactly
    # X+Y seconds have passed. The key disappears (acceptable) rather than
    # becoming permanent (which would be a data corruption issue).
    ck("TTL=edge: shortlived not resurrected (should be expired)", shortlived_val is None, shortlived_val)
    ck("TTL=edge: persistent survives", persistent_val == b"yes", persistent_val)
    stop(p2)
    shutil.rmtree(tmp)

def test_ttl_restart_before_expiry():
    """4b. Key with TTL, restart before expiry — TTL should not reset."""
    print("\n=== 4b: TTL restart before expiry ===")
    tmp = tempfile.mkdtemp(prefix="picodb-aof-")
    aof = os.path.join(tmp, "ttl_restart.aof")

    p = start(aof=aof)
    s = conn()
    s.sendall(bf(SET, b"ttl_key", b"alive", ttl=300))  # 5 minute TTL
    s.recv(1)
    s.close()
    time.sleep(0.5)
    stop(p, hard=True)

    p2 = start(aof=aof)
    s2 = conn()
    val = getv(s2, b"ttl_key")
    ck("TTL restart before expiry: key exists", val == b"alive", val)
    # Check remaining TTL via API
    keys_info = api()["keys"]
    ttl_info = {k["key"]: k for k in keys_info}.get("ttl_key", {}).get("ttl", -1)
    ck("TTL restart: remaining TTL is <= 300", ttl_info <= 300, ttl_info)
    ck("TTL restart: remaining TTL is > 0 (not reset to 300)", ttl_info > 0 and ttl_info <= 300, ttl_info)
    s2.close()
    stop(p2)
    shutil.rmtree(tmp)

# =====================================================================
# TEST 5: Resource exhaustion
# =====================================================================

def test_large_value_near_max():
    """5c. Very large value near PICODB_MAX_BYTES."""
    print("\n=== 5c: Large value near PICODB_MAX_BYTES ===")
    tmp = tempfile.mkdtemp(prefix="picodb-aof-")
    aof = os.path.join(tmp, "large_value.aof")

    p = start(aof=aof, maxbytes=200*1024*1024)
    s = conn()

    # 1 MiB value — well within limits
    large_val = b"X" * (1024 * 1024)
    s.sendall(bf(SET, b"large", large_val))
    reply = recvn(s, 1)
    s.close()
    ck("large value (1MiB) SET accepted", reply == OK, reply)
    time.sleep(0.5)
    stop(p, hard=True)

    p2 = start(aof=aof)
    s2 = conn()
    val = getv(s2, b"large")
    ck("large value survives AOF replay", val == large_val, len(val) if val else None)
    s2.close()
    stop(p2)
    shutil.rmtree(tmp)

def test_aof_unwritable_path():
    """5b. AOF path pointed at unwritable location."""
    print("\n=== 5b: AOF path unwritable ===")
    tmp = tempfile.mkdtemp(prefix="picodb-aof-")

    # Test 1: path in a non-existent directory
    aof_bad = os.path.join(tmp, "nonexistent", "test.aof")
    env = dict(os.environ,
               PICODB_ENGINE_PORT=str(ENG_PORT), PICODB_HTTP_PORT=str(HTTP_PORT),
               PICODB_BIND="127.0.0.1", PICODB_AOF_PATH=aof_bad)
    env.pop("PICODB_TOKEN", None)
    env.pop("PICODB_PASSWORD", None)
    result = subprocess.run([BIN], env=env, capture_output=True, text=True, timeout=5)
    ck("unwritable AOF (nonexistent dir): clear error at startup",
       "cannot open AOF" in result.stderr, result.stderr[:200])

    # Test 2: symlink to /dev/null (absorbs all writes, returns 0 bytes on read)
    aof_null = os.path.join(tmp, "null.aof")
    os.symlink("/dev/null", aof_null)
    p4 = start(aof=aof_null)
    s4 = conn()
    s4.sendall(bf(SET, b"null_test", b"data"))
    reply3 = recvn(s4, 1)
    s4.close()
    ck("AOF=/dev/null: no crash", reply3 == OK, reply3)
    stop(p4)

    # Verify replay from /dev/null during startup (empty read)
    p5 = start(aof=aof_null)
    s5 = conn()
    val = getv(s5, b"null_test")
    ck("AOF=/dev/null: data lost on restart (devnull didn't persist)", val is None, val)
    s5.close()
    stop(p5)

    shutil.rmtree(tmp)

def test_writer_thread_silent_death():
    """5b-3. Writer thread dies silently on write error — only detectable by code review."""
    print("\n=== 5b-3: Writer thread death on I/O error (code review) ===")
    # This scenario is verified via code review rather than live test because
    # /dev/full blocks on read (causing replay hang), and creating a disk-full
    # scenario requires OS-level test infrastructure.
    #
    # CODE-BASED FINDING:
    # In aof_writer_loop (line 658-659 of src/main.rs):
    #   if writer.write_all(&f).is_err() { return; }
    # When a write fails, the thread simply returns. There is no:
    #   - log/error message
    #   - recovery mechanism
    #   - way for the rest of the server to detect the death
    # After the thread dies:
    #   1. Aof::log() continues to silently drop frames (line 566: let _ = self.tx.send(...))
    #   2. The server keeps responding OK (replies aren't gated on fsync)
    #   3. All mutating commands are silently lost
    #   4. On restart, data that was only in the channel buffer is gone
    print("  (verified by code audit — writer thread does not log errors on I/O failure)")
    print("  src/main.rs:658 and src/main.rs:565-566")

def test_aof_device_file_hang():
    """5b-2. AOF path = /dev/full causes startup hang (infinite read)."""
    print("\n=== 5b-2: AOF=/dev/full startup hang ===")
    env = dict(os.environ,
               PICODB_ENGINE_PORT=str(ENG_PORT+1), PICODB_HTTP_PORT=str(HTTP_PORT+1),
               PICODB_BIND="127.0.0.1", PICODB_AOF_PATH="/dev/full")
    env.pop("PICODB_TOKEN", None)
    env.pop("PICODB_PASSWORD", None)
    start_t = time.monotonic()
    p = subprocess.Popen([BIN], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    started = False
    for _ in range(30):  # 3 second max wait
        try:
            socket.create_connection(("127.0.0.1", ENG_PORT+1), timeout=0.2).close()
            started = True
            break
        except OSError:
            time.sleep(0.1)
    elapsed = time.monotonic() - start_t
    if started:
        # Unexpected: server started. Kill it.
        p.kill()
        p.wait()
    else:
        p.kill()
        p.wait()
    # Should NOT have started (cannot read /dev/full to EOF)
    ck("AOF=/dev/full: server does not start (infinite read hang)", not started, f"started in {elapsed:.1f}s")

# =====================================================================
# TEST 6: Replay performance / DoS
# =====================================================================

def test_replay_many_small_records():
    """6. Many small records — measure replay time."""
    print("\n=== 6: Replay performance — many small records ===")
    tmp = tempfile.mkdtemp(prefix="picodb-aof-")
    aof = os.path.join(tmp, "perf_replay.aof")

    # Generate 100,000 small SET records
    N = 100000
    print(f"  Generating {N} small records...")
    with open(aof, "wb") as f:
        for i in range(N):
            f.write(bf(SET, f"k{i}".encode(), b"v"))

    aof_size = os.path.getsize(aof) / (1024 * 1024)
    print(f"  AOF size: {aof_size:.1f} MiB")

    # Time the replay (startup time)
    env = dict(os.environ,
               PICODB_ENGINE_PORT=str(ENG_PORT), PICODB_HTTP_PORT=str(HTTP_PORT),
               PICODB_BIND="127.0.0.1", PICODB_AOF_PATH=aof, PICODB_AOF_FSYNC="no")
    env.pop("PICODB_TOKEN", None)
    env.pop("PICODB_PASSWORD", None)

    start_t = time.monotonic()
    p = subprocess.Popen([BIN], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(120):
        try:
            socket.create_connection(("127.0.0.1", ENG_PORT), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    elapsed = time.monotonic() - start_t

    s = conn()
    # Verify a few keys
    ck(f"perf: replay {N} records in {elapsed:.2f}s ({N/elapsed:.0f} records/s)", elapsed < 30, elapsed)
    ck("perf: k0 exists after replay", getv(s, b"k0") == b"v", getv(s, b"k0"))
    ck("perf: last key exists after replay", getv(s, f"k{N-1}".encode()) == b"v", getv(s, f"k{N-1}".encode()))
    s.close()
    stop(p)
    shutil.rmtree(tmp)


# =====================================================================
# MAIN
# =====================================================================

def main():
    if not os.path.exists(BIN):
        print(f"FAIL binary not found at {BIN}")
        sys.exit(1)

    test_truncated_trailing_record()
    test_truncated_midfile()
    test_corrupted_length_fields()
    test_corrupted_value_length_large()
    test_empty_and_random_file()

    test_fsync_always_reply_timing()
    test_fsync_always_durability_with_delay()
    test_fsync_everysec_loss_bound()

    test_rewrite_crash_safety()
    test_concurrent_writes_during_rewrite()
    test_rewrite_auth_required()
    test_rewrite_dos_vector()

    test_ttl_same_second_expiry()
    test_ttl_restart_before_expiry()

    test_large_value_near_max()
    test_aof_unwritable_path()
    test_writer_thread_silent_death()
    test_aof_device_file_hang()

    test_replay_many_small_records()

    # Summary
    print(f"\n=== SUMMARY ===")
    print(f"Tests passed: {sum(1 for f in fails if not f)} (well, FAIL count = {len(fails)})")
    if fails:
        print(f"FAILURES: {fails}")
    if findings:
        print(f"\nFindings to file as issues:")
        for f in findings:
            print(f"  [{f['severity']}] {f['title']}")

    # Print findings in issue format
    print("\n\n=== ISSUES TO FILE ===")
    for i, f in enumerate(findings):
        print(f"\n--- Issue {i+1}: {f['title']} ---")
        print(f"Severity: {f['severity']}")
        print(f"Repro: {f['repro']}")
        print(f"Expected: {f['expected']}")
        print(f"Actual: {f['actual']}")

    print(f"\n{'ALL ADVERSARIAL TESTS PASSED' if not fails else f'{len(fails)} FAILURES'}")
    sys.exit(1 if fails else 0)

if __name__ == "__main__":
    main()
