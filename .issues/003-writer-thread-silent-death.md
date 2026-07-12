---
title: "AOF writer thread dies silently on I/O error, silently losing all subsequent mutations"
labels: ["aof", "security", "data-loss"]
severity: "data loss"
---

## Description

When the AOF writer thread encounters an I/O error (disk full, permissions changed, filesystem remounted read-only), it exits silently with no logging, no error propagation, and no way for the rest of the server to detect the failure. After the thread dies, `Aof::log()` silently drops all frames, and the server continues to return `OK` for mutating commands — giving callers the false impression that their data is durably stored.

## Location

- **Thread exit on write error**: `src/main.rs:658-659`
  ```rust
  AofMsg::Frame(f) => {
      if writer.write_all(&f).is_err() {
          return; // <-- silent exit, no logging
      }
  ```
- **Silent frame drop**: `src/main.rs:565-566`
  ```rust
  fn log(&self, frame: Vec<u8>) {
      let _ = self.tx.send(AofMsg::Frame(frame)); // <-- error silently discarded
  }
  ```
- **Persist failure**: `src/main.rs:624-625`
  ```rust
  let persist = |writer: &mut BufWriter<File>, sync: bool| -> bool {
      if writer.flush().is_err() {
          return false; // <-- caller at line 697 will exit the thread on false
      }
  ```

## Repro

1. Start PicoDB with a valid AOF path.
2. Write some data (confirmed persisted).
3. Replace the AOF file behind the server's back with a symlink to `/dev/full` (or fill the disk).
4. Trigger a write via the engine protocol — the writer thread dies silently.
5. Continue writing — all replies are `OK`, but data is never written to disk.
6. On restart, all data written after step 4 is gone.

A more easily reproduced variant: start with `PICODB_AOF_PATH` pointing to a symlink to `/dev/null`, write data, confirm it doesn't persist across restart. (The writer thread survives with `/dev/null` because writes succeed — but `/dev/full` would kill it.)

## Impact

- **Silent data loss**: operators have no indication that persistence has failed.
- **False durability guarantees**: every mutating command returns OK, but the data exists only in memory and in the channel buffer.
- **Backup illusion**: users believe their data is safe, but a crash or restart will reveal the loss.

## Suggested Fix

At minimum, the writer thread should log the I/O error before exiting. More robustly:

1. Use a health-check mechanism: expose a "writer alive" flag that `Aof::log()` can check.
2. When the writer is dead, the server should either:
   - Reject mutating commands with an error response, or
   - Attempt to re-spawn the writer thread.
3. The `Flush` message handler (used during graceful shutdown) already detects failure — extend this to periodic health checks.
