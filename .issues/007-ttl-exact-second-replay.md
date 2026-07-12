---
title: "TTL expiry at exact replay second: key silently lost (conservative) or becomes persistent (if check changes)"
labels: ["aof", "cosmetic"]
severity: "cosmetic"
---

## Description

When a key's absolute TTL timestamp equals the current UNIX time during replay, the check `ttl_field as u64 <= now` (`src/main.rs:774`) correctly treats it as expired and skips it. This means the key is lost ≤1 second before its actual expiry time. While the conservative behavior is correct, the alternative (if the check were accidentally changed to `<`) would cause the key to become persistent (`ttl = 0` means no expiry).

## Location

`src/main.rs:773-781`:
```rust
let ttl = if action == ACT_SET && ttl_field != 0 {
    if ttl_field as u64 <= now {
        pos += total; // already expired — don't resurrect it
        continue;
    }
    (ttl_field as u64 - now) as u32
} else {
    0
};
```

## Impact

- **Current behavior (with `<=`)**: Conservative. Keys expire up to 1 second early on replay. This is acceptable for most use cases.
- **If check were `lt`**: A key with `ttl_field == now` would get `ttl = (now - now) = 0`, meaning "no expiry" — the key would become persistent. This is a latent bug waiting for a code change.

## Suggested Fix

Consider using a small grace window instead of exact comparison. If `ttl_field > now` but within 1-2 seconds, load the key with a 1-second relative TTL rather than skipping it entirely. This avoids the borderline case while still respecting the intended expiry.
