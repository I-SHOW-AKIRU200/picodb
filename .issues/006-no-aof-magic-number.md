---
title: "AOF file has no magic number or format identifier — any file is silently interpreted as valid AOF"
labels: ["aof", "security", "cosmetic"]
severity: "cosmetic"
---

## Description

The AOF file format has no magic number, version identifier, or checksum. When `PICODB_AOF_PATH` is accidentally pointed at a non-AOF file (a log file, a binary blob, or anything else), the server will attempt to replay the file's bytes as frames. While most random data will be rejected by the length checks, sufficiently large files with coincidental byte patterns could produce phantom keys or values.

## Location

`src/main.rs:751-799` (`replay_aof`). The function directly reads and interprets the file without any format validation:

```rust
let data = match std::fs::read(path) {
    Ok(d) => d,
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
    Err(e) => return Err(e),
};
// ... immediately starts interpreting bytes as frames
```

## Repro

```bash
# Create a random binary file
dd if=/dev/urandom of=/tmp/random.bin bs=4096 count=1

# Start PicoDB with this as the AOF
PICODB_AOF_PATH=/tmp/random.bin ./target/release/picodb
# Server starts successfully, may have replayed "commands" from random bytes
```

## Impact

- **Silent misconfiguration**: an operator who accidentally sets the wrong path won't get an error — the server will start and may have phantom data.
- **Poisoned replay**: if the random file happens to contain byte sequences that decode as valid SET commands, keys with garbage values could silently appear in the cache.

## Suggested Fix

1. Write a 4-byte magic number at the start of every AOF file (e.g., `Pico` or `\x00AOF`).
2. During replay, verify the magic number matches. If it doesn't, either:
   - Fail with a clear error (strict mode), or
   - Log a warning and treat the file as empty (lenient mode for recovery).
