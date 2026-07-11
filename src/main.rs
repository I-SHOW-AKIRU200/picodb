//! PicoDB — an ultra-low-latency, zero-dependency in-memory key/value cache.
//!
//! A single standalone binary that replaces Redis for volatile storage. It runs
//! two concurrent async listeners:
//!
//!   * **:7120** — raw binary wire protocol (the database engine).
//!   * **:7121** — a hand-rolled HTTP/1.1 endpoint serving a live dashboard,
//!                 a JSON `/api/keys` feed, and Prometheus `/metrics`.
//!
//! Storage is a `HashMap` behind an `Arc<RwLock>`, values carry an optional TTL
//! (lazy expiration on read), and a hard RAM cap is enforced by O(1) LRU
//! eviction. No web framework, no serde, no HTTP crate — only `tokio` (minimal
//! features) and the standard library.
//!
//! ## Binary wire protocol (request frame, port 7120)
//! ```text
//!  offset  size  field
//!  ------  ----  ---------------------------------------------------------
//!    0      1    Action Type  (0x01 SET | 0x02 GET | 0x03 DEL | 0x04 FLUSH
//!                              | 0x05 SUBSCRIBE | 0x06 PUBLISH)
//!    1      2    Key Length    u16, big-endian
//!    3      4    Value Length  u32, big-endian
//!    7      4    TTL seconds   u32, big-endian  (0 = no expiry)
//!   11      K    Key Data      (K = Key Length bytes)
//!   11+K    V    Value Data    (V = Value Length bytes)
//! ```
//! The fixed header is exactly **11 bytes**; the body length is `K + V`.
//!
//! ## Response frames
//! ```text
//!  [0x00]            Success (SET / DEL / FLUSH / PUBLISH / SUBSCRIBE ack)
//!  [0x00] + payload  Success for GET (payload = the stored value)
//!  [0x44]            Missing (key not found / expired on GET or DEL)  ('D')
//!  [0xFF]            System / parse error
//! ```
//!
//! ## Pub/Sub delivery frame (server -> subscriber, port 7120)
//! After a SUBSCRIBE ack, each PUBLISH to that channel pushes:
//! ```text
//!  [0x00] | [Payload Length: 4 bytes, big-endian] | [Payload Data]
//! ```

use std::collections::HashMap;
use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// Fixed request header: 1 (action) + 2 (key len) + 4 (value len) + 4 (ttl).
const HEADER_LEN: usize = 11;

// Action bytes (offset 0 of every request frame).
const ACT_SET: u8 = 0x01;
const ACT_GET: u8 = 0x02;
const ACT_DEL: u8 = 0x03;
const ACT_FLUSH: u8 = 0x04;
const ACT_SUBSCRIBE: u8 = 0x05;
const ACT_PUBLISH: u8 = 0x06;
const ACT_AUTH: u8 = 0x07; // authenticate: token carried in the key field, vlen=0

// Response status bytes (offset 0 of every response frame).
const RSP_OK: u8 = 0x00;
const RSP_MISSING: u8 = 0x44; // 'D' — data missing
const RSP_AUTH: u8 = 0x41; // 'A' — auth required / invalid token
const RSP_ERROR: u8 = 0xFF;

/// Hard upper bound on a single frame body (`key + value`) — guards the
/// per-connection accumulator against a client advertising an absurd length.
const MAX_FRAME_BODY: usize = 64 * 1024 * 1024;

/// Reusable per-connection stack buffer size, as specified.
const READ_BUF: usize = 4096;

const PORT_ENGINE: u16 = 7120;
const PORT_HTTP: u16 = 7121;

/// Current UNIX time in whole seconds (monotonic-enough for TTL accounting).
#[inline]
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ===========================================================================
// Storage: TTL-aware O(1) LRU cache (standard library only).
//
// Recency ordering is an intrusive doubly-linked list threaded through a slab
// (`Vec<Option<Node>>`); nodes reference each other by *index*, so there is no
// `unsafe` and no per-op heap allocation for the list. Every operation
// (get / set / del / evict) is O(1). Each node additionally stores `expires_at`
// and `last_accessed` for lazy expiration and access tracking.
// ===========================================================================

struct Node {
    key: Vec<u8>,
    value: Vec<u8>,
    expires_at: Option<u64>, // UNIX seconds; None = persistent
    last_accessed: u64,      // UNIX seconds of most recent GET/SET
    prev: Option<usize>,     // toward MRU (head)
    next: Option<usize>,     // toward LRU (tail)
}

struct LruCache {
    map: HashMap<Vec<u8>, usize>, // key -> slab index
    nodes: Vec<Option<Node>>,     // slab of live/freed nodes
    free: Vec<usize>,             // recycled slab indices
    head: Option<usize>,          // most-recently-used
    tail: Option<usize>,          // least-recently-used (evicted first)
    used: usize,                  // approximate live bytes
    cap: usize,                   // hard RAM ceiling in bytes
}

/// Fixed per-entry bookkeeping estimate (map bucket + node struct + Vec headers)
/// added to raw key/value bytes so accounting tracks real RSS, not payload only.
const ENTRY_OVERHEAD: usize = 72;

#[inline]
fn entry_size(key: &[u8], value: &[u8]) -> usize {
    key.len() + value.len() + ENTRY_OVERHEAD
}

impl LruCache {
    fn new(cap: usize) -> Self {
        LruCache {
            map: HashMap::new(),
            nodes: Vec::new(),
            free: Vec::new(),
            head: None,
            tail: None,
            used: 0,
            cap,
        }
    }

    /// Detach `idx` from the recency list (its slab slot stays allocated).
    fn unlink(&mut self, idx: usize) {
        let (prev, next) = {
            let n = self.nodes[idx].as_ref().unwrap();
            (n.prev, n.next)
        };
        match prev {
            Some(p) => self.nodes[p].as_mut().unwrap().next = next,
            None => self.head = next, // idx was head
        }
        match next {
            Some(nx) => self.nodes[nx].as_mut().unwrap().prev = prev,
            None => self.tail = prev, // idx was tail
        }
        let n = self.nodes[idx].as_mut().unwrap();
        n.prev = None;
        n.next = None;
    }

    /// Insert `idx` at the head (mark most-recently-used).
    fn push_front(&mut self, idx: usize) {
        let old_head = self.head;
        {
            let n = self.nodes[idx].as_mut().unwrap();
            n.prev = None;
            n.next = old_head;
        }
        if let Some(h) = old_head {
            self.nodes[h].as_mut().unwrap().prev = Some(idx);
        }
        self.head = Some(idx);
        if self.tail.is_none() {
            self.tail = Some(idx); // list was empty
        }
    }

    #[inline]
    fn move_to_front(&mut self, idx: usize) {
        if self.head == Some(idx) {
            return; // already MRU
        }
        self.unlink(idx);
        self.push_front(idx);
    }

    /// Allocate a slab slot, reusing a freed index when possible.
    fn alloc(&mut self, node: Node) -> usize {
        if let Some(i) = self.free.pop() {
            self.nodes[i] = Some(node);
            i
        } else {
            self.nodes.push(Some(node));
            self.nodes.len() - 1
        }
    }

    /// Remove a known slab index completely (map + list + byte counter).
    fn remove_idx(&mut self, idx: usize) {
        self.unlink(idx);
        let node = self.nodes[idx].take().unwrap();
        self.map.remove(&node.key);
        self.used = self.used.saturating_sub(entry_size(&node.key, &node.value));
        self.free.push(idx);
    }

    /// Drop the LRU (tail) entry. Returns false if the cache is empty.
    fn evict_lru(&mut self) -> bool {
        match self.tail {
            Some(t) => {
                self.remove_idx(t);
                true
            }
            None => false,
        }
    }

    /// Insert or update a key with an optional expiry, then evict from the LRU
    /// end until back under the RAM cap. O(1) amortized.
    fn set(&mut self, key: Vec<u8>, value: Vec<u8>, expires_at: Option<u64>, now: u64) {
        if let Some(&idx) = self.map.get(&key) {
            let old_sz = {
                let n = self.nodes[idx].as_ref().unwrap();
                entry_size(&n.key, &n.value)
            };
            let new_sz = {
                let n = self.nodes[idx].as_mut().unwrap();
                n.value = value;
                n.expires_at = expires_at;
                n.last_accessed = now;
                entry_size(&n.key, &n.value)
            };
            self.used = self.used - old_sz + new_sz;
            self.move_to_front(idx);
        } else {
            let sz = entry_size(&key, &value);
            let idx = self.alloc(Node {
                key: key.clone(),
                value,
                expires_at,
                last_accessed: now,
                prev: None,
                next: None,
            });
            self.map.insert(key, idx);
            self.used += sz;
            self.push_front(idx);
        }

        // Enforce the ceiling. Keep at least the just-written entry even if a
        // single value alone exceeds the cap (best-effort bound, never a panic).
        while self.used > self.cap && self.map.len() > 1 {
            if !self.evict_lru() {
                break;
            }
        }
    }

    /// Retrieve a value, applying **lazy expiration**: an expired key is dropped
    /// instantly and treated as missing. On a live hit the entry is promoted to
    /// MRU, `last_accessed` is updated, and the reply `[0x00] + value` is written
    /// **directly into `out`** (no intermediate allocation / clone). Returns true
    /// on hit so the caller can bump the hit/miss counters.
    fn get_into(&mut self, key: &[u8], now: u64, out: &mut Vec<u8>) -> bool {
        let Some(&idx) = self.map.get(key) else {
            return false;
        };
        // Lazy expiration check (offset into node's expires_at).
        if let Some(exp) = self.nodes[idx].as_ref().unwrap().expires_at {
            if exp <= now {
                self.remove_idx(idx);
                return false;
            }
        }
        {
            let n = self.nodes[idx].as_mut().unwrap();
            n.last_accessed = now;
            out.push(RSP_OK); // [0x00] + payload, copied once straight to the wire buffer
            out.extend_from_slice(&n.value);
        }
        self.move_to_front(idx);
        true
    }

    /// Explicitly remove a key. Returns true if it existed (expired counts as
    /// missing and is cleaned up).
    fn del(&mut self, key: &[u8], now: u64) -> bool {
        let Some(&idx) = self.map.get(key) else {
            return false;
        };
        let expired = self.nodes[idx]
            .as_ref()
            .unwrap()
            .expires_at
            .map(|e| e <= now)
            .unwrap_or(false);
        self.remove_idx(idx);
        !expired
    }

    /// Wipe all data instantly and release backing capacity.
    fn flush(&mut self) {
        self.map = HashMap::new();
        self.nodes = Vec::new();
        self.free = Vec::new();
        self.head = None;
        self.tail = None;
        self.used = 0;
    }

    /// Snapshot for the dashboard: (key, value_size, ttl_remaining_seconds).
    /// Expired entries are skipped (but not removed here — that stays lazy).
    fn snapshot(&self, now: u64) -> Vec<(Vec<u8>, usize, Option<u64>)> {
        let mut out = Vec::with_capacity(self.map.len());
        for (key, &idx) in self.map.iter() {
            let n = self.nodes[idx].as_ref().unwrap();
            let ttl = match n.expires_at {
                Some(e) if e <= now => continue, // hide already-expired keys
                Some(e) => Some(e - now),
                None => None,
            };
            out.push((key.clone(), n.value.len(), ttl));
        }
        out
    }
}

// ===========================================================================
// Shared server state (single Arc, cloned into every connection task).
// ===========================================================================

/// Registry of pub/sub subscribers: channel -> list of delivery senders.
type SubMap = HashMap<Vec<u8>, Vec<mpsc::UnboundedSender<Vec<u8>>>>;

struct Server {
    cache: RwLock<LruCache>,
    subs: Mutex<SubMap>,
    hits: AtomicU64,
    misses: AtomicU64,
    start: Instant,
    auth: Option<Vec<u8>>, // shared secret token; None = auth disabled
}

impl Server {
    fn new(cap: usize, auth: Option<Vec<u8>>) -> Self {
        Server {
            cache: RwLock::new(LruCache::new(cap)),
            subs: Mutex::new(HashMap::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            start: Instant::now(),
            auth,
        }
    }

    /// True when no token is configured (auth disabled) or `tok` matches it.
    /// Uses a constant-time compare so a wrong token leaks no length/content
    /// timing signal.
    fn token_ok(&self, tok: &[u8]) -> bool {
        match &self.auth {
            None => true,
            Some(secret) => ct_eq(tok, secret),
        }
    }
}

/// Constant-time byte-slice equality: always scans the whole length, no early
/// exit on first mismatch. Length mismatch fails fast (length isn't secret).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Recover a poisoned lock instead of propagating the panic — one wedged task
/// must never take down the whole server.
macro_rules! lock_or_recover {
    ($e:expr) => {
        match $e {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    };
}

// ===========================================================================
// Binary engine (port 7120)
// ===========================================================================

/// Dispatch one decoded command, appending its reply bytes to `out`.
/// Operates on borrowed key/value **slices** (only SET must copy, since it
/// stores the data) and appends to a shared reply buffer so a whole pipelined
/// batch is answered with a single socket write. SUBSCRIBE is handled by the
/// caller since it hijacks the connection.
fn apply_into(server: &Server, action: u8, key: &[u8], value: &[u8], ttl: u32, out: &mut Vec<u8>) {
    let now = now_secs();
    match action {
        ACT_SET => {
            let expires_at = if ttl > 0 { Some(now + ttl as u64) } else { None };
            let mut cache = lock_or_recover!(server.cache.write());
            cache.set(key.to_vec(), value.to_vec(), expires_at, now);
            out.push(RSP_OK);
        }
        ACT_GET => {
            // GET mutates recency + may lazily expire, so it takes the write lock.
            let mut cache = lock_or_recover!(server.cache.write());
            if cache.get_into(key, now, out) {
                server.hits.fetch_add(1, Ordering::Relaxed);
            } else {
                server.misses.fetch_add(1, Ordering::Relaxed);
                out.push(RSP_MISSING);
            }
        }
        ACT_DEL => {
            let mut cache = lock_or_recover!(server.cache.write());
            out.push(if cache.del(key, now) { RSP_OK } else { RSP_MISSING });
        }
        ACT_FLUSH => {
            let mut cache = lock_or_recover!(server.cache.write());
            cache.flush();
            out.push(RSP_OK);
        }
        ACT_PUBLISH => {
            // Broadcast `value` to every live subscriber of channel `key`.
            // Pruning is lazy: senders whose receiver has dropped fail to send
            // and are retained-out here.
            let mut subs = lock_or_recover!(server.subs.lock());
            if let Some(list) = subs.get_mut(key) {
                list.retain(|tx| tx.send(value.to_vec()).is_ok());
                if list.is_empty() {
                    subs.remove(key);
                }
            }
            out.push(RSP_OK);
        }
        _ => out.push(RSP_ERROR), // unknown action byte
    }
}

/// Decode the 11-byte header at `buf[pos..]`. Returns (action, klen, vlen, ttl).
#[inline]
fn decode_header(b: &[u8]) -> (u8, usize, usize, u32) {
    let action = b[0]; //                                    offset 0
    let klen = u16::from_be_bytes([b[1], b[2]]) as usize; // offset 1..3
    let vlen = u32::from_be_bytes([b[3], b[4], b[5], b[6]]) as usize; // offset 3..7
    let ttl = u32::from_be_bytes([b[7], b[8], b[9], b[10]]); //        offset 7..11
    (action, klen, vlen, ttl)
}

/// Per-connection worker for the binary engine.
///
/// Reads are pulled into a reusable stack buffer `[u8; 4096]` and appended to a
/// small accumulator; complete frames are drained each pass. This makes both
/// fragmented (multi-packet) and pipelined (batched) transmission safe.
async fn handle_engine_conn(mut stream: TcpStream, server: Arc<Server>) {
    let _ = stream.set_nodelay(true);

    // Pre-authenticated only when the server runs open (no token configured).
    let mut authed = server.auth.is_none();

    let mut read_buf = [0u8; READ_BUF]; // reused every read; no per-read heap alloc
    let mut acc: Vec<u8> = Vec::new();
    let mut out: Vec<u8> = Vec::with_capacity(READ_BUF); // batched replies; reused every cycle

    loop {
        out.clear();
        let mut pos = 0usize;
        while acc.len() - pos >= HEADER_LEN {
            let (action, klen, vlen, ttl) = decode_header(&acc[pos..pos + HEADER_LEN]);

            if klen + vlen > MAX_FRAME_BODY {
                let _ = stream.write_all(&out).await; // flush replies already earned
                let _ = stream.write_all(&[RSP_ERROR]).await;
                return; // desync — safest to drop the connection
            }

            let total = HEADER_LEN + klen + vlen;
            if acc.len() - pos < total {
                break; // frame not fully arrived yet
            }

            // Body slices borrow `acc` directly — no per-op key/value allocation.
            // key = [11 .. 11+K],  value = [11+K .. 11+K+V]
            let kstart = pos + HEADER_LEN;
            let vstart = kstart + klen;
            let vend = vstart + vlen;

            // AUTH (0x07): token is in the key field. Sets per-connection state.
            if action == ACT_AUTH {
                authed = server.token_ok(&acc[kstart..vstart]);
                out.push(if authed { RSP_OK } else { RSP_AUTH });
                pos += total;
                continue;
            }

            // Every other command requires a prior successful AUTH.
            if !authed {
                out.push(RSP_AUTH);
                pos += total;
                continue;
            }

            if action == ACT_SUBSCRIBE {
                // SUBSCRIBE hijacks the connection. Flush any pending batched
                // replies first, then hand the socket to the push loop.
                let channel = acc[kstart..vstart].to_vec();
                pos += total;
                if !out.is_empty() && stream.write_all(&out).await.is_err() {
                    return;
                }
                acc.drain(0..pos);
                subscribe_loop(stream, server, channel).await;
                return;
            }

            apply_into(
                &server,
                action,
                &acc[kstart..vstart],
                &acc[vstart..vend],
                ttl,
                &mut out,
            );
            pos += total;
        }

        if pos > 0 {
            acc.drain(0..pos);
        }

        // ONE write syscall per read-cycle amortizes the whole pipelined batch.
        if !out.is_empty() && stream.write_all(&out).await.is_err() {
            return; // client went away mid-write
        }

        match stream.read(&mut read_buf).await {
            Ok(0) => return,                                // clean EOF
            Ok(n) => acc.extend_from_slice(&read_buf[..n]), // append & re-parse
            Err(_) => return,                               // reset / half-open
        }
    }
}

/// After SUBSCRIBE, register a delivery channel and forward every PUBLISH to the
/// socket until the client disconnects. Concurrency between "peer closed" and
/// "message to deliver" is resolved with `tokio::select!`.
async fn subscribe_loop(mut stream: TcpStream, server: Arc<Server>, channel: Vec<u8>) {
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    {
        let mut subs = lock_or_recover!(server.subs.lock());
        subs.entry(channel).or_default().push(tx);
    }

    // Acknowledge the subscription.
    if stream.write_all(&[RSP_OK]).await.is_err() {
        return;
    }

    let mut sink = [0u8; READ_BUF]; // drains/detects client-side close
    loop {
        tokio::select! {
            // Detect disconnect (or ignore any further client bytes).
            r = stream.read(&mut sink) => {
                match r {
                    Ok(0) | Err(_) => return, // peer closed / reset -> drop (sender pruned lazily on next publish)
                    Ok(_) => continue,        // subscribers don't issue commands; ignore
                }
            }
            // Deliver a published payload:  [0x00] | [len u32 BE] | [payload]
            msg = rx.recv() => {
                match msg {
                    Some(payload) => {
                        let mut frame = Vec::with_capacity(5 + payload.len());
                        frame.push(RSP_OK);
                        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                        frame.extend_from_slice(&payload);
                        if stream.write_all(&frame).await.is_err() {
                            return;
                        }
                    }
                    None => return, // all senders dropped
                }
            }
        }
    }
}

// ===========================================================================
// HTTP dashboard + metrics (port 7121) — hand-rolled HTTP/1.1, no framework.
// ===========================================================================

/// The dashboard page is baked into the binary at compile time.
const DASHBOARD_HTML: &str = include_str!("dashboard.html");

/// Minimal, allocation-light HTTP/1.1 handler. Reads until the end of headers
/// (`\r\n\r\n`), parses only the request line, and routes on the path. Any
/// malformed input yields a clean 400 rather than a panic.
async fn handle_http_conn(mut stream: TcpStream, server: Arc<Server>) {
    let _ = stream.set_nodelay(true);

    let mut read_buf = [0u8; READ_BUF];
    let mut req: Vec<u8> = Vec::new();

    // Read until headers complete or we exceed a sane header cap (16 KiB).
    let headers_done = loop {
        match stream.read(&mut read_buf).await {
            Ok(0) => break false, // client closed before sending a full request
            Ok(n) => {
                req.extend_from_slice(&read_buf[..n]);
                if find_subslice(&req, b"\r\n\r\n").is_some() {
                    break true;
                }
                if req.len() > 16 * 1024 {
                    break false; // oversized headers -> treat as bad request
                }
            }
            Err(_) => return, // reset / half-open
        }
    };

    if !headers_done {
        let _ = write_http(&mut stream, 400, "text/plain", b"Bad Request").await;
        return;
    }

    // Parse the request line: "METHOD SP PATH SP HTTP/1.1".
    let path = match parse_request_target(&req) {
        Some(p) => p,
        None => {
            let _ = write_http(&mut stream, 400, "text/plain", b"Bad Request").await;
            return;
        }
    };

    // Route (ignore any query string on the path).
    let route = path.split('?').next().unwrap_or("/");

    // Auth gate for data-bearing routes. `/` (the static shell) stays open so
    // the browser can load and prompt for a token — it exposes no cache data.
    let authorized = server.auth.is_none() || {
        match http_token(&req, &path) {
            Some(tok) => server.token_ok(tok.as_bytes()),
            None => false,
        }
    };

    // WebSocket upgrade: GET /ws with a Sec-WebSocket-Key header -> 101 + hijack.
    if route == "/ws" {
        if !authorized {
            let _ = write_http(&mut stream, 401, "text/plain", b"Unauthorized").await;
            return;
        }
        match header_value(&req, "sec-websocket-key") {
            Some(key) => {
                let resp = format!(
                    "HTTP/1.1 101 Switching Protocols\r\n\
                     Upgrade: websocket\r\n\
                     Connection: Upgrade\r\n\
                     Sec-WebSocket-Accept: {}\r\n\r\n",
                    ws_accept(&key)
                );
                if stream.write_all(resp.as_bytes()).await.is_ok() {
                    handle_ws(stream, server).await; // runs until the socket closes
                }
            }
            None => {
                let _ = write_http(&mut stream, 400, "text/plain", b"Bad WebSocket Request").await;
            }
        }
        return;
    }

    match route {
        "/" => {
            let _ = write_http(&mut stream, 200, "text/html; charset=utf-8", DASHBOARD_HTML.as_bytes()).await;
        }
        "/metrics" if authorized => {
            let body = render_metrics(&server);
            let _ = write_http(&mut stream, 200, "text/plain; version=0.0.4", body.as_bytes()).await;
        }
        "/api/keys" if authorized => {
            let body = render_api_keys(&server);
            let _ = write_http(&mut stream, 200, "application/json", body.as_bytes()).await;
        }
        "/metrics" | "/api/keys" => {
            let _ = write_http(&mut stream, 401, "text/plain", b"Unauthorized").await;
        }
        _ => {
            let _ = write_http(&mut stream, 404, "text/plain", b"Not Found").await;
        }
    }
}

/// Extract an auth token from a request: `Authorization: Bearer <t>` header, or
/// a `?token=<t>` query parameter on the target (browsers/WS can't set headers
/// on some requests, so the query form is the fallback).
fn http_token(req: &[u8], target: &str) -> Option<String> {
    if let Some(h) = header_value(req, "authorization") {
        if let Some(rest) = h.strip_prefix("Bearer ").or_else(|| h.strip_prefix("bearer ")) {
            return Some(rest.trim().to_string());
        }
    }
    if let Some(q) = target.split('?').nth(1) {
        for pair in q.split('&') {
            if let Some(v) = pair.strip_prefix("token=") {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Extract the request target (path) from the raw request bytes.
fn parse_request_target(req: &[u8]) -> Option<String> {
    // First line ends at the first CRLF.
    let line_end = find_subslice(req, b"\r\n")?;
    let line = &req[..line_end];
    let text = std::str::from_utf8(line).ok()?;
    let mut parts = text.split(' ');
    let _method = parts.next()?; // GET/POST/... — accepted uniformly
    let target = parts.next()?;
    if target.is_empty() {
        return None;
    }
    Some(target.to_string())
}

/// Naive substring search (no regex/crate); fine for tiny request buffers.
fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Write a complete HTTP/1.1 response with an explicit Content-Length and
/// `Connection: close` (we serve one response per connection).
async fn write_http(stream: &mut TcpStream, status: u16, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "OK",
    };
    // Advertise Bearer auth on 401 so standard clients know how to authenticate.
    let extra = if status == 401 {
        "WWW-Authenticate: Bearer\r\n"
    } else {
        ""
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {ctype}\r\n\
         Content-Length: {}\r\n\
         {extra}\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

/// Prometheus plain-text exposition.
fn render_metrics(server: &Server) -> String {
    let uptime = server.start.elapsed().as_secs();
    let hits = server.hits.load(Ordering::Relaxed);
    let misses = server.misses.load(Ordering::Relaxed);
    let (mem, keys) = {
        let cache = lock_or_recover!(server.cache.read());
        (cache.used, cache.map.len())
    };

    let mut s = String::with_capacity(512);
    s.push_str("# HELP picodb_uptime_seconds Seconds since the server started.\n");
    s.push_str("# TYPE picodb_uptime_seconds counter\n");
    s.push_str(&format!("picodb_uptime_seconds {uptime}\n"));

    s.push_str("# HELP picodb_memory_usage_bytes Approximate bytes held by the cache.\n");
    s.push_str("# TYPE picodb_memory_usage_bytes gauge\n");
    s.push_str(&format!("picodb_memory_usage_bytes {mem}\n"));

    s.push_str("# HELP picodb_total_keys Current number of live keys.\n");
    s.push_str("# TYPE picodb_total_keys gauge\n");
    s.push_str(&format!("picodb_total_keys {keys}\n"));

    s.push_str("# HELP picodb_hits_total Total successful GETs.\n");
    s.push_str("# TYPE picodb_hits_total counter\n");
    s.push_str(&format!("picodb_hits_total {hits}\n"));

    s.push_str("# HELP picodb_misses_total Total GET misses (absent or expired).\n");
    s.push_str("# TYPE picodb_misses_total counter\n");
    s.push_str(&format!("picodb_misses_total {misses}\n"));

    s
}

/// Hand-rolled JSON for `/api/keys` (no serde). Keys are rendered as UTF-8
/// (lossy) strings with the mandatory JSON escapes applied.
fn render_api_keys(server: &Server) -> String {
    let now = now_secs();
    let uptime = server.start.elapsed().as_secs();
    let hits = server.hits.load(Ordering::Relaxed);
    let misses = server.misses.load(Ordering::Relaxed);

    let (mem, total, entries) = {
        let cache = lock_or_recover!(server.cache.read());
        (cache.used, cache.map.len(), cache.snapshot(now))
    };

    let mut s = String::with_capacity(256 + entries.len() * 48);
    s.push('{');
    s.push_str(&format!("\"uptime_seconds\":{uptime},"));
    s.push_str(&format!("\"memory_usage_bytes\":{mem},"));
    s.push_str(&format!("\"total_keys\":{total},"));
    s.push_str(&format!("\"hits\":{hits},"));
    s.push_str(&format!("\"misses\":{misses},"));
    s.push_str("\"keys\":[");
    for (i, (key, size, ttl)) in entries.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str("{\"key\":\"");
        json_escape_into(&mut s, key);
        s.push_str(&format!("\",\"size\":{size},\"ttl\":"));
        match ttl {
            Some(t) => s.push_str(&t.to_string()),
            None => s.push_str("null"),
        }
        s.push('}');
    }
    s.push_str("]}");
    s
}

/// Append `bytes` (as UTF-8 lossy) to `out`, escaping per the JSON string spec.
fn json_escape_into(out: &mut String, bytes: &[u8]) {
    for ch in String::from_utf8_lossy(bytes).chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}

// ===========================================================================
// WebSocket bridge (RFC 6455) — hand-rolled, zero-dependency, on port 7121.
//
// The raw binary pub/sub on :7120 is the *fast* real-time path (no upgrade, no
// masking). WebSocket exists only so browsers — which cannot open raw TCP — can
// receive the same live feed. A WS client gets:
//   * a live cache-stats JSON push every second (replaces dashboard polling),
//   * a live pub/sub bridge: send a text frame naming a channel, then receive
//     every PUBLISH to that channel (fanned out through the same Server.subs).
// ===========================================================================

/// RFC 3174 SHA-1. Only needed to compute the handshake accept key.
fn sha1(msg: &[u8]) -> [u8; 20] {
    let (mut h0, mut h1, mut h2, mut h3, mut h4) =
        (0x6745_2301u32, 0xEFCD_AB89u32, 0x98BA_DCFEu32, 0x1032_5476u32, 0xC3D2_E1F0u32);
    let ml = (msg.len() as u64).wrapping_mul(8);
    let mut data = msg.to_vec();
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&ml.to_be_bytes());

    for chunk in data.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = if i < 20 {
                ((b & c) | ((!b) & d), 0x5A82_7999u32)
            } else if i < 40 {
                (b ^ c ^ d, 0x6ED9_EBA1)
            } else if i < 60 {
                ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC)
            } else {
                (b ^ c ^ d, 0xCA62_C1D6)
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }
    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

/// Standard base64 encoder (with `=` padding).
fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for ch in data.chunks(3) {
        let b0 = ch[0] as u32;
        let b1 = *ch.get(1).unwrap_or(&0) as u32;
        let b2 = *ch.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        out.push(if ch.len() > 1 { T[(n >> 6 & 63) as usize] as char } else { '=' });
        out.push(if ch.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}

/// Compute `Sec-WebSocket-Accept` from the client's `Sec-WebSocket-Key`.
fn ws_accept(client_key: &str) -> String {
    const MAGIC: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut buf = client_key.trim().as_bytes().to_vec();
    buf.extend_from_slice(MAGIC);
    base64(&sha1(&buf))
}

/// Build a server→client WebSocket frame: FIN set, **never masked**, with the
/// 7 / 16 / 64-bit length encoding per RFC 6455 §5.2.
fn encode_ws(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(payload.len() + 10);
    f.push(0x80 | (opcode & 0x0f)); // FIN + opcode
    let len = payload.len();
    if len < 126 {
        f.push(len as u8);
    } else if len <= 0xFFFF {
        f.push(126);
        f.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        f.push(127);
        f.extend_from_slice(&(len as u64).to_be_bytes());
    }
    f.extend_from_slice(payload);
    f
}

/// Read one client→server frame. Client frames are always masked; we XOR-unmask.
/// Returns `(opcode, payload)`, or `None` on EOF / malformed / oversized frame.
/// (Assumes unfragmented frames — browsers send small unfragmented text/control.)
async fn read_ws_message<R: AsyncReadExt + Unpin>(rd: &mut R) -> Option<(u8, Vec<u8>)> {
    let mut h = [0u8; 2];
    rd.read_exact(&mut h).await.ok()?;
    let opcode = h[0] & 0x0f;
    let masked = h[1] & 0x80 != 0;
    let mut len = (h[1] & 0x7f) as usize;
    if len == 126 {
        let mut e = [0u8; 2];
        rd.read_exact(&mut e).await.ok()?;
        len = u16::from_be_bytes(e) as usize;
    } else if len == 127 {
        let mut e = [0u8; 8];
        rd.read_exact(&mut e).await.ok()?;
        len = u64::from_be_bytes(e) as usize;
    }
    if len > MAX_FRAME_BODY {
        return None; // guard against an absurd advertised length
    }
    let mut mask = [0u8; 4];
    if masked {
        rd.read_exact(&mut mask).await.ok()?;
    }
    let mut payload = vec![0u8; len];
    rd.read_exact(&mut payload).await.ok()?;
    if masked {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[i & 3];
        }
    }
    Some((opcode, payload))
}

/// Case-insensitive HTTP header lookup over the raw request bytes.
fn header_value(req: &[u8], name_lower: &str) -> Option<String> {
    let text = String::from_utf8_lossy(req);
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break; // end of headers
        }
        if let Some(idx) = line.find(':') {
            if line[..idx].trim().eq_ignore_ascii_case(name_lower) {
                return Some(line[idx + 1..].trim().to_string());
            }
        }
    }
    None
}

/// Control events forwarded from the WS reader task to the writer loop.
enum Ctrl {
    Close,
    Ping(Vec<u8>),
}

// WebSocket opcodes.
const WS_TEXT: u8 = 0x1;
const WS_BIN: u8 = 0x2;
const WS_CLOSE: u8 = 0x8;
const WS_PING: u8 = 0x9;
const WS_PONG: u8 = 0xA;

/// Drive one upgraded WebSocket connection until it closes.
///
/// The socket is split so reads live in a dedicated task — this keeps the
/// `select!` writer loop cancel-safe (a stats tick can never truncate a partial
/// frame read). Subscriptions reuse `Server.subs`, the exact registry that the
/// binary `PUBLISH` path fans out to.
async fn handle_ws(stream: TcpStream, server: Arc<Server>) {
    let (mut rd, mut wr) = stream.into_split();
    let (ctrl_tx, mut ctrl_rx) = mpsc::unbounded_channel::<Ctrl>();
    let (msg_tx, mut msg_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Reader task: parse client frames; control -> ctrl_tx, subscribe -> subs.
    let server_r = Arc::clone(&server);
    tokio::spawn(async move {
        loop {
            match read_ws_message(&mut rd).await {
                Some((WS_CLOSE, _)) | None => {
                    let _ = ctrl_tx.send(Ctrl::Close);
                    break;
                }
                Some((WS_PING, payload)) => {
                    if ctrl_tx.send(Ctrl::Ping(payload)).is_err() {
                        break;
                    }
                }
                Some((WS_TEXT, payload)) | Some((WS_BIN, payload)) => {
                    // A text/binary frame naming a channel = subscribe request.
                    if !payload.is_empty() {
                        let mut subs = lock_or_recover!(server_r.subs.lock());
                        subs.entry(payload).or_default().push(msg_tx.clone());
                    }
                }
                Some(_) => {} // pong / reserved: ignore
            }
        }
    });

    // Writer loop: every branch is cancel-safe (interval tick + mpsc recv).
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                // Live stats push (first tick fires immediately).
                let json = render_api_keys(&server);
                if wr.write_all(&encode_ws(WS_TEXT, json.as_bytes())).await.is_err() {
                    return;
                }
            }
            m = msg_rx.recv() => {
                if let Some(payload) = m {
                    // Live pub/sub message -> binary WS frame.
                    if wr.write_all(&encode_ws(WS_BIN, &payload)).await.is_err() {
                        return;
                    }
                }
            }
            c = ctrl_rx.recv() => {
                match c {
                    Some(Ctrl::Ping(p)) => {
                        if wr.write_all(&encode_ws(WS_PONG, &p)).await.is_err() {
                            return;
                        }
                    }
                    Some(Ctrl::Close) | None => {
                        let _ = wr.write_all(&encode_ws(WS_CLOSE, &[])).await;
                        return;
                    }
                }
            }
        }
    }
}

// ===========================================================================
// Configuration + entrypoint
// ===========================================================================

fn config_cap() -> usize {
    env::var("PICODB_MAX_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(50 * 1024 * 1024) // 50 MiB default cap
}

/// Read the shared auth token from `PICODB_TOKEN`. An empty/unset value means
/// auth is disabled. The token itself is never logged.
fn config_token() -> Option<Vec<u8>> {
    match env::var("PICODB_TOKEN") {
        Ok(t) if !t.is_empty() => Some(t.into_bytes()),
        _ => None,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cap = config_cap();
    let auth = config_token();
    let auth_status = if auth.is_some() {
        "enabled"
    } else {
        "DISABLED (set PICODB_TOKEN)"
    };

    // Single shared state. `std::sync::RwLock` (not tokio's async lock) is
    // deliberate: critical sections are pure in-memory ops with no `.await`
    // inside, so a blocking lock is faster and never starves the runtime.
    let server = Arc::new(Server::new(cap, auth));

    let engine = TcpListener::bind(("127.0.0.1", PORT_ENGINE)).await?;
    let http = TcpListener::bind(("127.0.0.1", PORT_HTTP)).await?;

    eprintln!(
        "PicoDB up — engine :{PORT_ENGINE} (binary) · dashboard http://127.0.0.1:{PORT_HTTP}/ · RAM cap {} MiB · auth: {auth_status}",
        cap / (1024 * 1024)
    );

    // Binary engine accept loop (spawned so both listeners run concurrently).
    let engine_srv = Arc::clone(&server);
    let engine_task = tokio::spawn(async move {
        loop {
            match engine.accept().await {
                Ok((stream, _)) => {
                    let s = Arc::clone(&engine_srv);
                    tokio::spawn(handle_engine_conn(stream, s));
                }
                Err(_) => continue, // transient accept error must not kill the loop
            }
        }
    });

    // HTTP dashboard accept loop.
    let http_srv = Arc::clone(&server);
    let http_task = tokio::spawn(async move {
        loop {
            match http.accept().await {
                Ok((stream, _)) => {
                    let s = Arc::clone(&http_srv);
                    tokio::spawn(handle_http_conn(stream, s));
                }
                Err(_) => continue,
            }
        }
    });

    // Run until either listener loop ends (they don't, absent process signals).
    let _ = tokio::join!(engine_task, http_task);
    Ok(())
}
