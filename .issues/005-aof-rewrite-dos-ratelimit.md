---
title: "AOF rewrite endpoint lacks rate limiting, enabling disk I/O DoS"
labels: ["aof", "security", "denial-of-service"]
severity: "denial of service"
---

## Description

The `POST /aof/rewrite` endpoint has no rate limiting. While concurrent rewrites are deduplicated (via the `rewriting` atomic flag), an attacker can still rapidly trigger the operation, causing the server to repeatedly snapshot the entire dataset and contend for the read lock — resulting in excessive disk I/O and CPU usage.

## Root Cause

`src/main.rs:1553-1565`:
```rust
"/aof/rewrite" if method == "POST" && authorized => {
    let (code, msg): (u16, &[u8]) = if server.aof.is_none() {
        (409, b"AOF disabled")
    } else if trigger_aof_rewrite(&server) {
        (202, b"rewrite started")
    } else {
        (409, b"rewrite already in progress")
    };
```

`trigger_aof_rewrite()` (`src/main.rs:2113-2129`) takes the cache read lock and iterates all entries to produce a compaction snapshot, even if a rewrite was just started:

```rust
let frames = {
    let cache = lock_or_recover!(server.cache.read());
    cache.dump_frames(now_secs())
};
```

When auth is disabled (no `PICODB_TOKEN` set), any client on the network can trigger this, making it an amplification-for-DoS vector.

## Repro

```bash
# Start server with no auth
PICODB_AOF_PATH=/tmp/test.aof PICODB_BIND=0.0.0.0 ./target/release/picodb &

# Rapid-fire rewrite requests
for i in {1..100}; do
    curl -X POST http://127.0.0.1:7121/aof/rewrite &
done
wait
```

Testing shows that even with deduplication, rapid requests cause multiple snapshot cycles (the `rewriting` flag is cleared when each rewrite finishes, allowing the next to proceed immediately).

## Impact

- Excessive disk I/O on the AOF path.
- Read-lock contention blocks concurrent reads during each snapshot.
- With auth disabled, any network-accessible client can trigger this.

## Suggested Fix

Add a minimum interval between rewrite operations (e.g., at least 60 seconds, matching Redis's auto-rewrite cadence). Track the timestamp of the last rewrite and reject requests that come too soon.

If auth is required for the endpoint, verify that the auth check is consistent — currently the endpoint does require authorization (line 1553), but when `PICODB_TOKEN` is not set, any request is authorized.
