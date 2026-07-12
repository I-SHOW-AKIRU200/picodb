---
title: "AOF replay treats mid-value truncated record as valid, silently corrupting data"
labels: ["aof", "security", "data-corruption"]
severity: "data corruption"
---

## Description

When a trailing record is truncated mid-value (not mid-header or mid-key), the replay path (`replay_aof`) does not detect it as a torn write. Instead, the truncated value bytes are treated as the beginning of the value, and subsequent bytes in the file (from the next record's header) are consumed as the remainder of the value. This produces a stored value that is a mix of real data and binary header bytes from subsequent frames.

## Root Cause

In `src/main.rs:762-766`, the truncated/corrupt tail detection checks:

```rust
if klen + vlen > MAX_FRAME_BODY || data.len() - pos < total {
    break; // truncated / corrupt tail — stop cleanly
}
```

This check passes when:
- The header is intact (so `klen` and `vlen` are valid-looking)
- The claimed `total` (`HEADER_LEN + klen + vlen`) does not exceed the remaining file data
- `klen + vlen <= MAX_FRAME_BODY`

A truncation that lands mid-value leaves the header intact and enough remaining file data (from subsequent records) to satisfy the length check. The replay has no mechanism to detect that the value was only partially written.

## Repro Steps

```python
import struct, socket, time, os, signal, tempfile

SET = 1
HEADER_LEN = 11
BIN = "./target/release/picodb"

def bf(a, k=b"", v=b"", t=0):
    return struct.pack(">BHII", a, len(k), len(v), t) + k + v

tmp = tempfile.mkdtemp(prefix="picodb-aof-")
aof = os.path.join(tmp, "corrupt.aof")

# Write 3 records, truncating the middle one mid-value
r2_full = bf(SET, b"k2", b"v2value")
with open(aof, "wb") as f:
    f.write(bf(SET, b"k1", b"v1"))          # full
    f.write(r2_full[:HEADER_LEN + 6])       # truncated mid-value (keeps "v2va")
    f.write(bf(SET, b"k3", b"v3"))          # full — consumed as part of k2's value

# Start server
p = subprocess.Popen([BIN], env={
    "PICODB_AOF_PATH": aof, "PICODB_ENGINE_PORT": "7390",
    "PICODB_HTTP_PORT": "7391", "PICODB_BIND": "127.0.0.1"
})
time.sleep(1)

s = socket.create_connection(("127.0.0.1", 7390))
# GET k2 — should be missing (torn write), but instead returns corrupted data
s.sendall(bytes([2, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]) + b"k2")  # GET k2
st = s.recv(1)
if st == b'\x44':  # MISS
    print("k2 missing (expected for torn write)")
else:
    ln = struct.unpack(">I", s.recv(4))[0]
    val = s.recv(ln)
    print(f"k2 = {val!r}")  # Shows b'v2va\x01\x00\x02' — corrupted!
```

**Expected**: k2 should be missing (torn write not replayed).

**Actual**: k2 is stored with value `b'v2va\x01\x00\x02'` — the first 4 bytes "v2va" from the truncated value, plus 4 bytes of k3's frame header (`\x01\x00\x02\x00`).

## Impact

- Any crash that truncates a frame mid-value (which is the most common case, since the value is the largest part of most frames) will silently corrupt data on replay.
- The corrupted value includes binary frame header bytes from subsequent records, potentially introducing control characters or large interpreted lengths downstream.
- Subsequent records after the truncated one are also lost (consumed as the corrupted value's tail), compounding the data loss.

## Suggested Fix

The replay path needs a way to distinguish "the file ends naturally with a complete record" from "the file was truncated mid-record." Options:

1. Add an AOF footer / checksum: write a magic footer + frame count after the last frame, and validate during replay. If the footer is missing or doesn't match, discard the last record.
2. Track the expected file size in a separate metadata file.
3. At minimum, log a warning when a truncated frame is detected, even if the heuristics don't identify it as torn.
