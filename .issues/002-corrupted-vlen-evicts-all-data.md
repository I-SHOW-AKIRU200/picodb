---
title: "Corrupted AOF value length (within MAX_FRAME_BODY) causes total cache eviction on replay"
labels: ["aof", "security", "data-loss"]
severity: "data loss"
---

## Description

A bit-flip corruption in a frame's value-length field can cause the replay path to load a huge value that exceeds the cache capacity (`PICODB_MAX_BYTES`, default 50 MiB), triggering LRU eviction of all previously replayed data. This turns a single-byte corruption into total data loss.

## Root Cause

Two independent limits exist but are not cross-checked:

- `MAX_FRAME_BODY = 64 MiB` (`src/main.rs:105`) — the maximum size of a single frame body (key + value)
- `PICODB_MAX_BYTES = 50 MiB` (default, `src/main.rs:2050-2054`) — the total cache capacity

A corrupted vlen of `64 MiB - 1` passes the replay guard at `src/main.rs:765`:

```rust
if klen + vlen > MAX_FRAME_BODY || data.len() - pos < total {
    break;
}
```

But when `apply_into` inserts this 64 MiB value into the 50 MiB cache, the `LruCache::enforce_cap()` evicts everything to make room — including all previously replayed keys (`src/main.rs:302-319`).

## Repro Steps

1. Create an AOF with 3 records: one anchor key, one victim key (vlen corrupted to 67108854), and one post key.
2. Pad the file so the corrupted record's claimed value size is satisfied.
3. Start PicoDB pointing to this AOF.
4. GET the anchor key — returns None (was evicted).

See `tests/test_aof_adversarial.py:test_corrupted_value_length_large` for a runnable reproduction.

## Impact

- A single-bit flip in the vlen field of any mid-file record can cause total data loss during replay.
- This is a realistic corruption scenario (disk bit rot, incomplete write).
- Unlike the frame being silently skipped, this actively destroys other data via the LRU eviction mechanism.

## Suggested Fix

Add a cross-check during replay: before applying a frame, verify that `klen + vlen <= server.cache.capacity` (or some fraction thereof). If the claimed value exceeds the cache capacity, skip the frame and log a warning.

Alternatively, reduce `MAX_FRAME_BODY` to something strictly less than `PICODB_MAX_BYTES` (or make it relative to the configured capacity).
