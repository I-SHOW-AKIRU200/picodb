# PicoDB

An ultra-low-latency, **zero-dependency** in-memory key/value cache in Rust — a lightweight, single-binary alternative to Redis for volatile storage.

- **Tiny**: ~2.3 MB idle RAM, ~540 KB stripped binary.
- **Fast**: ~16–22 µs GET latency and **3.2M+ pipelined ops/s** on loopback (beats Redis latency in local tests).
- **Zero deps**: only `tokio` (minimal features) + the standard library. The binary protocol parser, HTTP/1.1 server, WebSocket (RFC 6455), SHA-1, base64, and JSON are all hand-rolled.
- **Batteries included**: TTL + O(1) LRU eviction, pub/sub, a live web dashboard, Prometheus `/metrics`, and token auth.

> Not a full Redis replacement — no persistence, clustering, or rich data types. It's a fast, small, volatile cache with a real-time dashboard.

## Install

**One-line install** (clones the repo, installs Rust if needed, builds, generates an access token):

```bash
curl -fsSL https://raw.githubusercontent.com/I-SHOW-AKIRU200/picodb/main/install.sh | bash
```

**Or clone and run the CLI manually:**

```bash
git clone https://github.com/I-SHOW-AKIRU200/picodb.git && cd picodb && ./picodb
```

`./picodb` opens an interactive CLI (ASCII logo + arrow-key menu) that can **Setup** (install Rust if needed, build, and generate a random access token into `.env` — auth **on** by default), **Start** the server, **Test**, **Benchmark**, and **Regenerate token**. After install, start the server and open the dashboard at **http://127.0.0.1:7121/**, pasting the token from `.env` when prompted:

```bash
cd picodb && ./picodb run
```

It's also fully scriptable:

```bash
./picodb setup     # install Rust (if needed), build, generate token
./picodb run       # start the server (loads .env)
./picodb test      # run integration tests
./picodb bench     # build the native load generator
./picodb status    # build/auth/config status
./picodb token     # regenerate the access token
```

Prefer `make`? `make setup && make run`.

## Ports

| Port | Purpose |
|------|---------|
| `7120` | Raw binary wire protocol (the database engine) |
| `7121` | HTTP dashboard, `/metrics`, `/api/keys`, and WebSocket `/ws` |

Both bind to `127.0.0.1` only.

## Binary protocol (port 7120)

Fixed **11-byte** big-endian header, then key, then value:

```
 offset  size  field
 ------  ----  ----------------------------------------
   0      1    Action  (0x01 SET | 0x02 GET | 0x03 DEL | 0x04 FLUSH
                        | 0x05 SUBSCRIBE | 0x06 PUBLISH | 0x07 AUTH)
   1      2    Key Length    u16
   3      4    Value Length  u32
   7      4    TTL seconds   u32  (0 = no expiry; SET only)
  11      K    Key Data
  11+K    V    Value Data
```

Responses:

```
 [0x00]            OK           (SET/DEL/FLUSH/PUBLISH/SUBSCRIBE ack/AUTH ok)
 [0x00] + payload  OK for GET   (payload = stored value)
 [0x44]            Missing      ('D' — key not found / expired)
 [0x41]            Auth         ('A' — auth required or invalid token)
 [0xFF]            Error        (malformed frame / unknown action)
```

Pub/sub delivery frame (server → subscriber): `[0x00] | [len u32] | [payload]`.

### Client handshake

```
1. AUTH   (0x07)  token in key field           -> 0x00 ok | 0x41 rejected   (only if auth enabled)
2. SET    (0x01)  key, value, ttl              -> 0x00
   GET    (0x02)  key                          -> 0x00 + value | 0x44
   DEL    (0x03)  key                          -> 0x00 | 0x44
   FLUSH  (0x04)                               -> 0x00
3. SUBSCRIBE (0x05) channel  -> 0x00 ack, then push frames on every PUBLISH
   PUBLISH   (0x06) channel, payload -> 0x00 (fans out to subscribers)
```

## Real-time

- **Fastest path (apps/servers):** raw binary `SUBSCRIBE`/`PUBLISH` on `:7120` — no HTTP upgrade, no masking.
- **Browsers:** WebSocket at `ws://127.0.0.1:7121/ws` carries the same pub/sub feed plus a live stats push every second. (WebSocket exists because browsers can't open raw TCP; it's the compatibility path, not the fast path.)

## Configuration

| Env var | Default | Meaning |
|---------|---------|---------|
| `PICODB_TOKEN` | *(unset)* | Shared access token. Set → auth enforced on all surfaces. Unset → auth disabled (loopback dev). |
| `PICODB_MAX_BYTES` | `52428800` (50 MiB) | Hard RAM cap; oldest keys evicted (LRU) past it. |

## Security

- **Token auth** on the binary engine (`AUTH` command), HTTP dashboard/metrics/api, and WebSocket. Constant-time comparison; the token is never logged.
- **No built-in TLS** (would require a crypto dependency). PicoDB binds to loopback only. For access over an untrusted network, terminate TLS at a reverse proxy (nginx / caddy / stunnel) in front of `:7121` / `:7120`.
- Known limitations: single shared token (not per-user ACLs), no per-IP brute-force lockout, plaintext on the wire without a proxy.

## Development

```bash
./picodb        # interactive menu
make build      # compile release binary
make run        # start (loads .env)
make test       # run the Python integration tests
make bench      # build the native load generator
make clean
```

## License

MIT — see [LICENSE](LICENSE).
