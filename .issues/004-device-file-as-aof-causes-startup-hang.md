---
title: "Pointing AOF path at a character device (/dev/full) causes infinite hang on startup"
labels: ["aof", "security", "denial-of-service"]
severity: "denial of service"
---

## Description

Setting `PICODB_AOF_PATH` to a character device that never returns EOF (such as `/dev/full`, `/dev/zero`, or `/dev/urandom`) causes the server to hang indefinitely at startup during the AOF replay phase. The server never begins listening for connections and must be killed externally.

## Root Cause

In `src/main.rs:752`:
```rust
let data = match std::fs::read(path) {
```

`std::fs::read()` reads the file until EOF. For character devices like `/dev/full` or `/dev/zero`, this call never returns — the device keeps generating data indefinitely.

This is arguably a misconfiguration, but the server should handle it gracefully (fail fast with a clear error) rather than hang silently.

## Repro

```bash
PICODB_AOF_PATH=/dev/full PICODB_BIND=127.0.0.1 ./target/release/picodb
# Server hangs forever at startup
```

Also affects `/dev/zero`, `/dev/urandom`, and any FIFO/named pipe that doesn't return EOF.

## Impact

- Denial of service via misconfiguration.
- Can be triggered accidentally by setting `PICODB_AOF_PATH` to the wrong path.
- In containerized environments where `/dev/full` or `/dev/zero` might be the result of a bad volume mount.

## Suggested Fix

Before calling `std::fs::read()`, check if the path is a regular file using `path.metadata()?.is_file()`. If it's not a regular file (or a block device that supports EOF), reject it with a clear error message.

```rust
let meta = std::fs::metadata(path)?;
if !meta.is_file() {
    return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,
        format!("AOF path '{}' is not a regular file", path.display())));
}
```
