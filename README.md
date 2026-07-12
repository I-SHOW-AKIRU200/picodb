<p align="center">
  <img src="assets/picoDB.svg" alt="PicoDB" width="220" />
</p>

<h1 align="center">PicoDB</h1>

<p align="center">
  An ultra-low-latency, <b>zero-dependency</b> in-memory key/value cache in Rust —<br/>
  a lightweight, single-binary alternative to Redis for volatile storage.
</p>

<p align="center"><i>Created by AKIRU</i></p>

---

- **Tiny**: ~2.3 MB idle RAM, ~540 KB stripped binary.
- **Fast**: ~16–22 µs GET latency and **3.2M+ pipelined ops/s** on loopback (beats Redis latency in local tests).
- **Zero deps**: only `tokio` (minimal features) + the standard library. The binary protocol parser, HTTP/1.1 server, WebSocket (RFC 6455), SHA-1, base64, and JSON are all hand-rolled.
- **Redis-style data types**: strings, **hashes**, **lists**, and **sets** — not just plain key/value.
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

`./picodb` opens an interactive CLI (ASCII logo + arrow-key menu) that can **Setup** (install Rust if needed, build, and generate a random access token into `.env` — auth **on** by default), **Start** the server, **Test**, **Benchmark**, and **Regenerate token**.

<p align="center">
  <img src="assets/preview.jpg" alt="PicoDB CLI" width="720" />
</p>

After install, start the server and open the dashboard at **http://127.0.0.1:7121/**, pasting the token from `.env` when prompted:

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
                        | 0x05 SUBSCRIBE | 0x06 PUBLISH | 0x07 AUTH | 0x08 TYPE
                        | 0x10-0x14 hash | 0x20-0x25 list | 0x30-0x34 set)
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
   GET    (0x02)  key                          -> 0x00 [len u32][value] | 0x44
   DEL    (0x03)  key                          -> 0x00 | 0x44
   FLUSH  (0x04)                               -> 0x00
3. SUBSCRIBE (0x05) channel  -> 0x00 ack, then push frames on every PUBLISH
   PUBLISH   (0x06) channel, payload -> 0x00 (fans out to subscribers)
```

## Connect from your code

### Connection URI
```
picodb://[username:password@]host[:port]      # default port 7120 (binary engine)
```
The part before `@` is your **auth secret** — it must match the server's `PICODB_TOKEN`,
or `PICODB_USERNAME`/`PICODB_PASSWORD`. With a single token use an empty username:
`picodb://:<token>@host:7120`.

### Ready-made clients (zero dependencies)
- **Python** — [`examples/client.py`](examples/client.py)
- **Node.js** — [`examples/client.js`](examples/client.js)

```python
from client import PicoDB
db = PicoDB.from_uri("picodb://admin:change-me@localhost:7120")
db.set("user:1", "alice", ttl=3600)
print(db.get("user:1"))          # b'alice'
db.delete("user:1")
```

```js
const { PicoDB } = require("./client");
const db = await PicoDB.connect("picodb://admin:change-me@localhost:7120");
await db.set("user:1", "alice", 3600);
console.log((await db.get("user:1")).toString());  // "alice"
db.close();
```

> Note: the `picodb://` URI is a **client-side convention** the example clients parse; the
> server speaks the raw binary protocol above (host + port + AUTH), it doesn't parse URIs itself.

## Data types

Beyond plain strings, PicoDB supports Redis-style **hashes**, **lists**, and **sets**. A key holds one type; using the wrong command on a key returns a `0xFF` (WRONGTYPE) error, and collections that become empty are deleted automatically.

```python
db = PicoDB.from_uri("picodb://:token@localhost:7120")

# strings
db.set("name", "alice", ttl=60);   db.get("name")            # b'alice'

# hashes
db.hset("user:1", "email", "a@x.com");  db.hget("user:1", "email")
db.hgetall("user:1")                    # {b'email': b'a@x.com'}
db.hlen("user:1");  db.hdel("user:1", "email")

# lists
db.rpush("queue", "a", "b", "c");  db.lpush("queue", "z")
db.lrange("queue", 0, -1)               # [b'z', b'a', b'b', b'c']
db.lpop("queue");  db.rpop("queue");  db.llen("queue")

# sets
db.sadd("tags", "x", "y", "x");    db.scard("tags")          # 2 (deduped)
db.smembers("tags");  db.sismember("tags", "x");  db.srem("tags", "y")

db.type("user:1")                       # 'hash' | 'list' | 'set' | 'string' | 'none'
```

| Type | Commands |
|------|----------|
| string | `SET` (TTL) · `GET` · `DEL` |
| hash | `HSET` · `HGET` · `HDEL` · `HGETALL` · `HLEN` |
| list | `LPUSH` · `RPUSH` · `LPOP` · `RPOP` · `LRANGE` · `LLEN` |
| set | `SADD` · `SREM` · `SMEMBERS` · `SISMEMBER` · `SCARD` |
| any | `TYPE` · `DEL` · `FLUSH` |

The Node.js client (`examples/client.js`) exposes the same methods (`hset`, `rpush`, `sadd`, …).

## Authentication

Two interchangeable ways to set the secret in `.env`:

| Style | `.env` | Connect with |
|-------|--------|--------------|
| Single token | `PICODB_TOKEN=<token>` | `picodb://:<token>@host:7120` |
| User + password | `PICODB_USERNAME=admin`<br>`PICODB_PASSWORD=secret` | `picodb://admin:secret@host:7120` |

The same secret authenticates the HTTP surfaces. API clients send `Authorization: Bearer <secret>`
(e.g. Prometheus scraping `/metrics`); the browser dashboard exchanges the token once at `POST /login`
for an `HttpOnly`, `SameSite=Strict` session cookie — the token is never placed in a URL. The WebSocket
authenticates with that same cookie. Regenerate a random token anytime with `./picodb token`.

## Real-time

- **Fastest path (apps/servers):** raw binary `SUBSCRIBE`/`PUBLISH` on `:7120` — no HTTP upgrade, no masking.
- **Browsers:** WebSocket at `ws://127.0.0.1:7121/ws` carries the same pub/sub feed plus a live stats push every second (authenticated by the dashboard session cookie). WebSocket exists because browsers can't open raw TCP; it's the compatibility path, not the fast path.

## Configuration

All runtime settings live in `.env` (copy from [`.env.example`](.env.example)) — no code changes needed, like `redis.conf`.

| Env var | Default | Meaning |
|---------|---------|---------|
| `PICODB_BIND` | `127.0.0.1` | Bind address. `0.0.0.0` exposes on all interfaces (public). |
| `PICODB_ENGINE_PORT` | `7120` | TCP port for the raw binary engine. |
| `PICODB_HTTP_PORT` | `7121` | TCP port for the dashboard / metrics / API / WebSocket. |
| `PICODB_TOKEN` | *(unset)* | Shared access token. Set → auth enforced on all surfaces. Unset → auth disabled (loopback dev). |
| `PICODB_MAX_BYTES` | `52428800` (50 MiB) | Hard RAM cap; oldest keys evicted (LRU) past it. |

> Exposing publicly (`PICODB_BIND=0.0.0.0`)? Always set `PICODB_TOKEN`, open the port in your host/cloud firewall, and put TLS in front (reverse proxy) — traffic is otherwise plaintext.

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
