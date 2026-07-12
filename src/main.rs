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
//!  [0x00]                       Success (SET / DEL / FLUSH / AUTH / PUBLISH / SUBSCRIBE ack)
//!  [0x00][len u32 BE][value]    Success for GET (length-prefixed, self-delimiting)
//!  [0x44]                       Missing (key not found / expired on GET or DEL)  ('D')
//!  [0x41]                       Auth required / invalid token  ('A')
//!  [0xFF]                       System / parse error
//! ```
//!
//! ## Pub/Sub delivery frame (server -> subscriber, port 7120)
//! After a SUBSCRIBE ack, each PUBLISH to that channel pushes:
//! ```text
//!  [0x00] | [Payload Length: 4 bytes, big-endian] | [Payload Data]
//! ```

use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc as sync_mpsc;
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
const ACT_TYPE: u8 = 0x08; // report the value type of a key

// Hash commands. value field = length-prefixed args: [len u32][bytes]…
const ACT_HSET: u8 = 0x10; // args: field, value          -> int (1 new / 0 updated)
const ACT_HGET: u8 = 0x11; // args: field                 -> bulk | missing
const ACT_HDEL: u8 = 0x12; // args: field                 -> int (1 / 0)
const ACT_HGETALL: u8 = 0x13; // (no args)                -> array [field, value]…
const ACT_HLEN: u8 = 0x14; // (no args)                   -> int

// List commands.
const ACT_LPUSH: u8 = 0x20; // args: item…                -> int (new length)
const ACT_RPUSH: u8 = 0x21; // args: item…                -> int (new length)
const ACT_LPOP: u8 = 0x22; //  (no args)                  -> bulk | missing
const ACT_RPOP: u8 = 0x23; //  (no args)                  -> bulk | missing
const ACT_LRANGE: u8 = 0x24; // value = start i64 BE + stop i64 BE (16 bytes) -> array
const ACT_LLEN: u8 = 0x25; //  (no args)                  -> int

// Set commands.
const ACT_SADD: u8 = 0x30; // args: member…               -> int (added count)
const ACT_SREM: u8 = 0x31; // args: member…               -> int (removed count)
const ACT_SMEMBERS: u8 = 0x32; // (no args)               -> array [member]…
const ACT_SISMEMBER: u8 = 0x33; // args: member           -> int (0 / 1)
const ACT_SCARD: u8 = 0x34; //  (no args)                 -> int

// Response status bytes (offset 0 of every response frame).
const RSP_OK: u8 = 0x00;
const RSP_MISSING: u8 = 0x44; // 'D' — data missing
const RSP_AUTH: u8 = 0x41; // 'A' — auth required / invalid token
const RSP_ERROR: u8 = 0xFF;
const RSP_AOF_ERROR: u8 = 0x45; // 'E' — AOF write failed (writer thread dead)

/// Hard upper bound on a single frame body (`key + value`) — guards the
/// per-connection accumulator against a client advertising an absurd length.
const MAX_FRAME_BODY: usize = 64 * 1024 * 1024;

/// Magic bytes written at the start of every new AOF file. Used to detect
/// non-AOF files (device nodes, FIFOs — caught earlier) and to validate that
/// the file was produced by a compatible PicoDB version.
const AOF_MAGIC: &[u8; 5] = b"Pico1";

/// Reusable per-connection stack buffer size, as specified.
const READ_BUF: usize = 4096;

const DEFAULT_PORT_ENGINE: u16 = 7120;
const DEFAULT_PORT_HTTP: u16 = 7121;

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

/// A stored value — Redis-style data types, all held in-memory.
enum Value {
    Str(Vec<u8>),
    Hash(HashMap<Vec<u8>, Vec<u8>>),
    List(VecDeque<Vec<u8>>),
    Set(HashSet<Vec<u8>>),
}

/// Per-element bookkeeping estimate for collection types (map/list/set node).
const ELEM_OVERHEAD: usize = 24;

impl Value {
    /// Approximate heap bytes held by this value (payload + per-element overhead).
    fn mem_size(&self) -> usize {
        match self {
            Value::Str(v) => v.len(),
            Value::Hash(h) => h.iter().map(|(k, v)| k.len() + v.len() + ELEM_OVERHEAD).sum(),
            Value::List(l) => l.iter().map(|v| v.len() + ELEM_OVERHEAD).sum(),
            Value::Set(s) => s.iter().map(|v| v.len() + ELEM_OVERHEAD).sum(),
        }
    }
    fn type_name(&self) -> &'static str {
        match self {
            Value::Str(_) => "string",
            Value::Hash(_) => "hash",
            Value::List(_) => "list",
            Value::Set(_) => "set",
        }
    }
    /// Element count (for display); for strings this is the byte length.
    fn cardinality(&self) -> usize {
        match self {
            Value::Str(v) => v.len(),
            Value::Hash(h) => h.len(),
            Value::List(l) => l.len(),
            Value::Set(s) => s.len(),
        }
    }
    /// True for a collection that holds no elements (Redis deletes these).
    fn is_empty_collection(&self) -> bool {
        match self {
            Value::Str(_) => false,
            Value::Hash(h) => h.is_empty(),
            Value::List(l) => l.is_empty(),
            Value::Set(s) => s.is_empty(),
        }
    }
}

struct Node {
    key: Vec<u8>,
    value: Value,
    expires_at: Option<u64>, // UNIX seconds; None = persistent
    last_accessed: u64,      // UNIX seconds of most recent access
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
    evicted: Vec<Vec<u8>>,        // keys dropped by capacity eviction, pending AOF delete
}

/// Fixed per-entry bookkeeping estimate (map bucket + node struct + Vec headers)
/// added to raw key/value bytes so accounting tracks real RSS, not payload only.
const ENTRY_OVERHEAD: usize = 72;

#[inline]
fn entry_size(key: &[u8], value: &Value) -> usize {
    key.len() + value.mem_size() + ENTRY_OVERHEAD
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
            evicted: Vec::new(),
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

    /// Evict from the LRU tail until back under the RAM cap. Never evicts
    /// `keep_idx` (the entry a command just touched, always MRU).
    fn enforce_cap(&mut self, keep_idx: Option<usize>) {
        while self.used > self.cap && self.map.len() > 1 {
            if self.tail == keep_idx {
                break;
            }
            // Capture the key about to be evicted so the AOF can log a matching
            // delete — otherwise the evicted key's `SET` would resurrect on replay.
            let evicted_key = self
                .tail
                .map(|t| self.nodes[t].as_ref().unwrap().key.clone());
            if !self.evict_lru() {
                break;
            }
            if let Some(k) = evicted_key {
                self.evicted.push(k);
            }
        }
    }

    /// SET: insert/replace a key as a string value with optional expiry.
    fn set(&mut self, key: Vec<u8>, value: Value, expires_at: Option<u64>, now: u64) {
        if let Some(&idx) = self.map.get(&key) {
            let old_sz = self.node_size(idx);
            {
                let n = self.nodes[idx].as_mut().unwrap();
                n.value = value;
                n.expires_at = expires_at;
                n.last_accessed = now;
            }
            let new_sz = self.node_size(idx);
            self.used = self.used - old_sz + new_sz;
            self.move_to_front(idx);
            self.enforce_cap(Some(idx));
        } else {
            let idx = self.create(key, value, expires_at, now);
            self.enforce_cap(Some(idx));
        }
    }

    /// Create a brand-new key at the MRU position and return its slab index.
    fn create(&mut self, key: Vec<u8>, value: Value, expires_at: Option<u64>, now: u64) -> usize {
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
        idx
    }

    /// Look up a live key: applies lazy expiration, and on a hit promotes it to
    /// MRU and updates `last_accessed`. Returns the slab index, or None if the
    /// key is absent or expired (expired keys are dropped here).
    fn live_idx(&mut self, key: &[u8], now: u64) -> Option<usize> {
        let &idx = self.map.get(key)?;
        if let Some(exp) = self.nodes[idx].as_ref().unwrap().expires_at {
            if exp <= now {
                self.remove_idx(idx);
                return None;
            }
        }
        self.nodes[idx].as_mut().unwrap().last_accessed = now;
        self.move_to_front(idx);
        Some(idx)
    }

    #[inline]
    fn node_size(&self, idx: usize) -> usize {
        let n = self.nodes[idx].as_ref().unwrap();
        entry_size(&n.key, &n.value)
    }
    #[inline]
    fn value_ref(&self, idx: usize) -> &Value {
        &self.nodes[idx].as_ref().unwrap().value
    }
    #[inline]
    fn value_mut(&mut self, idx: usize) -> &mut Value {
        &mut self.nodes[idx].as_mut().unwrap().value
    }

    /// After mutating the value at `idx`, reconcile the byte counter against its
    /// pre-mutation size (`old`). Drops the key if it became an empty collection;
    /// otherwise enforces the RAM cap.
    fn commit(&mut self, idx: usize, old: usize) {
        if self.value_ref(idx).is_empty_collection() {
            self.remove_idx(idx);
            return;
        }
        let new = self.node_size(idx);
        if new >= old {
            self.used += new - old;
        } else {
            self.used = self.used.saturating_sub(old - new);
        }
        self.enforce_cap(Some(idx));
    }

    /// Explicitly remove a key (any type). Returns true if it existed and was
    /// not already expired.
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

    /// Snapshot for the dashboard: (key, type, size_bytes, element_count, ttl).
    /// Expired entries are skipped (but not removed here — that stays lazy).
    fn snapshot(&self, now: u64) -> Vec<(Vec<u8>, &'static str, usize, usize, Option<u64>)> {
        let mut out = Vec::with_capacity(self.map.len());
        for (key, &idx) in self.map.iter() {
            let n = self.nodes[idx].as_ref().unwrap();
            let ttl = match n.expires_at {
                Some(e) if e <= now => continue, // hide already-expired keys
                Some(e) => Some(e - now),
                None => None,
            };
            out.push((
                key.clone(),
                n.value.type_name(),
                n.value.mem_size(),
                n.value.cardinality(),
                ttl,
            ));
        }
        out
    }

    /// Serialize the entire live dataset into the minimal set of AOF frames that
    /// recreate it — the basis of log compaction (rewrite). Expired entries are
    /// skipped; a string's TTL is emitted as an **absolute** expiry (the format
    /// the replay path expects). Collections never carry a TTL in this protocol.
    fn dump_frames(&self, now: u64) -> Vec<Vec<u8>> {
        let mut out = Vec::with_capacity(self.map.len());
        for (key, &idx) in self.map.iter() {
            let n = self.nodes[idx].as_ref().unwrap();
            let ttl_abs = match n.expires_at {
                Some(e) if e <= now => continue, // already expired: don't persist
                Some(e) => e as u32,             // absolute unix seconds (fits until 2106)
                None => 0,
            };
            match &n.value {
                Value::Str(v) => out.push(encode_frame(ACT_SET, key, v, ttl_abs)),
                Value::Hash(h) => {
                    for (f, v) in h.iter() {
                        let mut args = Vec::with_capacity(8 + f.len() + v.len());
                        arr_item(&mut args, f);
                        arr_item(&mut args, v);
                        out.push(encode_frame(ACT_HSET, key, &args, 0));
                    }
                }
                Value::List(l) => {
                    let mut args = Vec::new();
                    for item in l.iter() {
                        arr_item(&mut args, item);
                    }
                    if !args.is_empty() {
                        out.push(encode_frame(ACT_RPUSH, key, &args, 0));
                    }
                }
                Value::Set(s) => {
                    let mut args = Vec::new();
                    for m in s.iter() {
                        arr_item(&mut args, m);
                    }
                    if !args.is_empty() {
                        out.push(encode_frame(ACT_SADD, key, &args, 0));
                    }
                }
            }
        }
        out
    }
}

// ===========================================================================
// Append-only file (AOF) persistence.
//
// Durability with the same zero-dependency ethos: every *mutating* command is
// appended to a log file (as its wire frame), and on startup the log is replayed
// through `apply_into` to rebuild memory. The AOF record format IS the request
// frame — so logging is a re-encode and replay is a re-decode, with no new
// serialization layer.
//
// A dedicated OS thread owns the file. `apply_into` is synchronous and runs under
// the cache write lock, so it can `send` a frame into a `std::sync::mpsc` channel
// directly — this keeps blocking `fsync`/file I/O off tokio's worker threads AND
// makes the log order exactly match apply order (the send happens while the lock
// is held, so concurrent connections can't interleave).
// ===========================================================================

/// Durability policy — how often the writer thread calls `fsync`.
#[derive(Clone, Copy, PartialEq)]
enum Fsync {
    /// `fsync` after every command. Strongest; throughput bounded by disk fsync
    /// latency. (Replies aren't gated on the fsync, so it's "flush immediately",
    /// not synchronous-ack.)
    Always,
    /// `fsync` at most once per second (Redis default). A power loss / OS crash
    /// loses ≤1s; a mere process crash loses nothing (writes reach the OS every
    /// batch). The hot path never blocks on disk. The balanced default.
    EverySec,
    /// Never explicitly `fsync`; the OS flushes on its own schedule. Fastest.
    /// Writes still reach the OS every batch (so a process crash loses nothing),
    /// but a power loss / OS crash can lose whatever the OS hadn't flushed yet.
    No,
}

impl Fsync {
    fn parse(s: &str) -> Fsync {
        match s.trim().to_ascii_lowercase().as_str() {
            "always" => Fsync::Always,
            "no" | "never" => Fsync::No,
            _ => Fsync::EverySec, // default / "everysec"
        }
    }
}

/// Messages sent to the writer thread.
enum AofMsg {
    /// Append one command frame to the log.
    Frame(Vec<u8>),
    /// Replace the log with this compacted snapshot (log rewrite / compaction).
    Rewrite(Vec<Vec<u8>>),
    /// Flush + fsync everything buffered, then acknowledge (graceful shutdown).
    Flush(sync_mpsc::Sender<()>),
}

/// Handle to the running AOF writer, held by `Server`.
struct Aof {
    tx: sync_mpsc::Sender<AofMsg>,
    size: Arc<AtomicU64>,       // approximate current on-disk size (rewrite trigger)
    rewrites: Arc<AtomicU64>,   // completed rewrites (exposed as a metric)
    rewriting: Arc<AtomicBool>, // a rewrite is queued/in-flight (dedupes triggers)
    healthy: Arc<AtomicBool>,   // false after an I/O error in the writer thread
    write_errors: Arc<AtomicU64>, // total write errors (exposed as a metric)
    last_rewrite: Arc<Mutex<Instant>>, // last rewrite start time (rate limiting)
    rewrite_min_interval: Duration,   // minimum interval between rewrites
}

impl Aof {
    /// Append a pre-encoded frame. Returns false if the writer is dead (I/O error).
    /// The caller should reject the write rather than silently proceeding memory-only.
    #[inline]
    fn log(&self, frame: Vec<u8>) -> bool {
        if !self.healthy.load(Ordering::Acquire) {
            self.write_errors.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        match self.tx.send(AofMsg::Frame(frame)) {
            Ok(()) => true,
            Err(_) => {
                self.healthy.store(false, Ordering::Release);
                self.write_errors.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Durably flush the log and block until the writer confirms (bounded wait).
    /// Called on graceful shutdown so a clean restart never loses buffered writes.
    fn flush_blocking(&self) {
        let (ack_tx, ack_rx) = sync_mpsc::channel();
        if self.tx.send(AofMsg::Flush(ack_tx)).is_ok() {
            let _ = ack_rx.recv_timeout(Duration::from_secs(2));
        }
    }
}

/// Total byte length of a set of frames (post-rewrite file size).
fn frames_len(frames: &[Vec<u8>]) -> u64 {
    frames.iter().map(|f| f.len() as u64).sum()
}

/// Open `path` for appending and spawn the dedicated writer thread. Returns the
/// `Aof` handle (or an I/O error if the file can't be opened).
fn spawn_aof_writer(path: PathBuf, policy: Fsync, min_interval: Duration) -> std::io::Result<Aof> {
    let file = OpenOptions::new().create(true).append(true).open(&path)?;
    let start_size = file.metadata().map(|m| m.len()).unwrap_or(0);
    // New file: write the magic header so future replays can validate format.
    let start_size = if start_size == 0 {
        use std::io::Write;
        let mut writer = std::io::BufWriter::new(&file);
        let _ = writer.write_all(AOF_MAGIC);
        let _ = writer.flush();
        AOF_MAGIC.len() as u64
    } else {
        start_size
    };

    let (tx, rx) = sync_mpsc::channel::<AofMsg>();
    let size = Arc::new(AtomicU64::new(start_size));
    let rewrites = Arc::new(AtomicU64::new(0));
    let rewriting = Arc::new(AtomicBool::new(false));
    let healthy = Arc::new(AtomicBool::new(true));
    let write_errors = Arc::new(AtomicU64::new(0));
    let last_rewrite = Arc::new(Mutex::new(
        Instant::now() - min_interval - Duration::from_secs(1), // allow first trigger immediately
    ));

    let (w_size, w_rewrites, w_rewriting, w_healthy, w_write_errors, w_last_rewrite) = (
        Arc::clone(&size),
        Arc::clone(&rewrites),
        Arc::clone(&rewriting),
        Arc::clone(&healthy),
        Arc::clone(&write_errors),
        Arc::clone(&last_rewrite),
    );

    std::thread::Builder::new()
        .name("picodb-aof".into())
        .spawn(move || {
            aof_writer_loop(path, policy, file, rx, w_size, w_rewrites, w_rewriting, w_healthy, w_write_errors, w_last_rewrite)
        })
        .expect("spawn PicoDB AOF writer thread");

    Ok(Aof { tx, size, rewrites, rewriting, healthy, write_errors, last_rewrite, rewrite_min_interval: min_interval })
}

/// The writer thread. Owns the file; drains the channel in batches; pushes each
/// batch to the OS (so acknowledged writes survive a process crash) and fsyncs to
/// disk per policy. `recv_timeout(1s)` doubles as the `EverySec` heartbeat.
fn aof_writer_loop(
    path: PathBuf,
    policy: Fsync,
    file: File,
    rx: sync_mpsc::Receiver<AofMsg>,
    size: Arc<AtomicU64>,
    rewrites: Arc<AtomicU64>,
    rewriting: Arc<AtomicBool>,
    healthy: Arc<AtomicBool>,
    write_errors: Arc<AtomicU64>,
    last_rewrite: Arc<Mutex<Instant>>,
) {
    let mark_dead = || {
        healthy.store(false, Ordering::Release);
        write_errors.fetch_add(1, Ordering::Relaxed);
    };
    let mut writer = BufWriter::new(file);
    let mut unsynced = false; // written to the OS but not yet fsynced (everysec/no)

    // Push the userspace buffer to the OS; fsync to disk only when `sync` is set.
    // Returns false if the underlying file is gone (writer should exit).
    let persist = |writer: &mut BufWriter<File>, sync: bool| -> bool {
        if writer.flush().is_err() {
            return false;
        }
        if sync {
            let _ = writer.get_ref().sync_data();
        }
        true
    };

    loop {
        // Block for the next message (the 1s timeout is the everysec fsync tick).
        let first = match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(m) => m,
            Err(sync_mpsc::RecvTimeoutError::Timeout) => {
                if unsynced && policy == Fsync::EverySec {
                    if writer.get_ref().sync_data().is_err() {
                        eprintln!("PicoDB: AOF fsync error");
                        mark_dead();
                        return;
                    }
                    unsynced = false;
                }
                continue;
            }
            Err(sync_mpsc::RecvTimeoutError::Disconnected) => {
                let _ = persist(&mut writer, true);
                return;
            }
        };

        // Drain this message plus everything already queued: batch frame writes so
        // one flush (and at most one fsync) covers the whole burst.
        let mut msg = Some(first);
        let mut wrote = false;
        let mut disconnected = false;
        while let Some(m) = msg {
            match m {
                AofMsg::Frame(f) => {
                    if let Err(e) = writer.write_all(&f) {
                        eprintln!("PicoDB: AOF write error: {e}");
                        mark_dead();
                        return;
                    }
                    size.fetch_add(f.len() as u64, Ordering::Relaxed);
                    wrote = true;
                }
                AofMsg::Rewrite(frames) => {
                    if wrote && !persist(&mut writer, false) {
                        eprintln!("PicoDB: AOF flush error before rewrite");
                        mark_dead();
                        return;
                    }
                    wrote = false;
                    if let Some(w) = rewrite_aof(&path, &frames) {
                        writer = w;
                        size.store(frames_len(&frames), Ordering::Relaxed);
                        rewrites.fetch_add(1, Ordering::Relaxed);
                        *last_rewrite.lock().unwrap() = Instant::now();
                        unsynced = false;
                    }
                    // On failure keep appending to the existing file (no data loss).
                    rewriting.store(false, Ordering::Relaxed);
                }
                AofMsg::Flush(ack) => {
                    wrote = false;
                    let _ = persist(&mut writer, true); // durable flush on request
                    unsynced = false;
                    let _ = ack.send(());
                }
            }
            match rx.try_recv() {
                Ok(next) => msg = Some(next),
                Err(sync_mpsc::TryRecvError::Empty) => msg = None,
                Err(sync_mpsc::TryRecvError::Disconnected) => {
                    msg = None;
                    disconnected = true;
                }
            }
        }

        if wrote {
            // Always push to the OS page cache; fsync to disk only on `always`.
            if !persist(&mut writer, policy == Fsync::Always) {
                eprintln!("PicoDB: AOF persist error");
                mark_dead();
                return;
            }
            unsynced = policy != Fsync::Always;
        }
        if disconnected {
            let _ = persist(&mut writer, true);
            return;
        }
    }
}

/// Compact the log: write `frames` to a sibling temp file, fsync it, atomically
/// rename it over the live path, and hand back a fresh appending writer. Returns
/// `None` on any I/O error (caller keeps the old file — no data loss).
fn rewrite_aof(path: &Path, frames: &[Vec<u8>]) -> Option<BufWriter<File>> {
    // "<path>.tmp" regardless of the original extension.
    let mut tmp_os = path.as_os_str().to_owned();
    tmp_os.push(".tmp");
    let tmp = PathBuf::from(tmp_os);

    let write_tmp = || -> std::io::Result<()> {
        let mut f = BufWriter::new(
            OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?,
        );
        for frame in frames {
            f.write_all(frame)?;
        }
        f.flush()?;
        f.get_ref().sync_data()?; // land the temp durably before the rename
        std::fs::rename(&tmp, path)?; // atomic swap on the same filesystem
        Ok(())
    };
    if let Err(e) = write_tmp() {
        eprintln!("PicoDB: AOF rewrite failed: {e}");
        let _ = std::fs::remove_file(&tmp);
        return None;
    }
    match OpenOptions::new().create(true).append(true).open(path) {
        Ok(file) => Some(BufWriter::new(file)),
        Err(e) => {
            eprintln!("PicoDB: AOF reopen after rewrite failed: {e}");
            None
        }
    }
}

/// Replay a saved AOF into `cache`, rebuilding state. Runs once at startup, before
/// the server begins serving — and before the writer is installed, so replayed
/// commands are NOT re-logged. Returns the number of commands applied.
///
/// A `SET`'s TTL field holds an **absolute** expiry: convert it back to a relative
/// TTL, and skip keys that already expired. Corruption at the tail (a partially
/// written final frame after a crash) is tolerated — replay stops there.
fn replay_aof(server: &Server, path: &Path) -> std::io::Result<u64> {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let now = now_secs();
    let cache_cap = server.cache.read().unwrap_or_else(|p| p.into_inner()).cap;
    let mut scratch = Vec::new(); // discarded replies
    // Skip the magic header if present (backward compat with pre-magic files).
    let mut pos = if data.len() >= AOF_MAGIC.len() && &data[..AOF_MAGIC.len()] == AOF_MAGIC {
        AOF_MAGIC.len()
    } else {
        0
    };
    let mut applied = 0u64;

    while data.len() - pos >= HEADER_LEN {
        let (action, klen, vlen, ttl_field) = decode_header(&data[pos..pos + HEADER_LEN]);
        let total = HEADER_LEN + klen + vlen;
        // Validate the frame: reject absurd lengths AND any claim that exceeds
        // remaining file bytes. This catches truncation at ANY offset within a
        // record (header, key, or value) when the torn write is at EOF.
        if klen + vlen > MAX_FRAME_BODY || data.len() - pos < total {
            break;
        }
        // Reject records whose value alone exceeds the cache capacity —
        // loading them would evict everything replayed so far.
        if klen + vlen > cache_cap {
            pos += total;
            continue;
        }
        let kstart = pos + HEADER_LEN;
        let vstart = kstart + klen;
        let vend = vstart + vlen;

        // SET carries an absolute expiry; other actions ignore the TTL field.
        //
        // Edge case: when ttl_field == now (expiry is *this very second*), `<=`
        // treats the key as already expired. This is a deliberate trade-off: a
        // write that expires during the same wall-clock second as replay would
        // have to expire within <1 s of being served. Existing clients already
        // hold the value in memory — skipping the re-insertion avoids a brief
        // resurrection that violates the intent of the TTL.
        let ttl = if action == ACT_SET && ttl_field != 0 {
            if ttl_field as u64 <= now {
                pos += total; // already expired — don't resurrect it
                continue;
            }
            (ttl_field as u64 - now) as u32
        } else {
            0
        };

        scratch.clear();
        apply_into(
            server,
            action,
            &data[kstart..vstart],
            &data[vstart..vend],
            ttl,
            &mut scratch,
        );
        applied += 1;
        pos += total;
    }

    // Evictions during replay aren't logged; discard any queued delete markers.
    server.cache.write().unwrap_or_else(|p| p.into_inner()).evicted.clear();
    Ok(applied)
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
    aof: Option<Aof>,      // append-only persistence; None = in-memory only
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
            aof: None,
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

// --- reply encoders (all replies begin with RSP_OK unless missing/error) ----
#[inline]
fn reply_int(out: &mut Vec<u8>, n: i64) {
    out.push(RSP_OK);
    out.extend_from_slice(&n.to_be_bytes()); // [0x00][i64 BE]
}
#[inline]
fn reply_bulk(out: &mut Vec<u8>, data: &[u8]) {
    out.push(RSP_OK);
    out.extend_from_slice(&(data.len() as u32).to_be_bytes()); // [0x00][len u32][bytes]
    out.extend_from_slice(data);
}
#[inline]
fn arr_header(out: &mut Vec<u8>, count: u32) {
    out.push(RSP_OK);
    out.extend_from_slice(&count.to_be_bytes()); // [0x00][count u32] then count × item
}
#[inline]
fn arr_item(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

/// Split a value payload into length-prefixed args: [len u32 BE][bytes]…
fn parse_args(mut v: &[u8]) -> Option<Vec<&[u8]>> {
    let mut args = Vec::new();
    while !v.is_empty() {
        if v.len() < 4 {
            return None;
        }
        let l = u32::from_be_bytes([v[0], v[1], v[2], v[3]]) as usize;
        v = &v[4..];
        if v.len() < l {
            return None;
        }
        args.push(&v[..l]);
        v = &v[l..];
    }
    Some(args)
}

/// True for the commands that change stored state — the ones the AOF must record.
/// Read-only commands and PUB/SUB are excluded. (SUBSCRIBE never reaches
/// `apply_into`; PUBLISH does but touches only the subscriber registry.)
#[inline]
fn is_mutating(action: u8) -> bool {
    matches!(
        action,
        ACT_SET
            | ACT_DEL
            | ACT_FLUSH
            | ACT_HSET
            | ACT_HDEL
            | ACT_LPUSH
            | ACT_RPUSH
            | ACT_LPOP
            | ACT_RPOP
            | ACT_SADD
            | ACT_SREM
    )
}

/// Dispatch one decoded command, appending its reply bytes to `out`.
/// Appends to a shared reply buffer so a whole pipelined batch is answered with
/// a single socket write. SUBSCRIBE is handled by the caller (it hijacks the
/// connection). WRONGTYPE / malformed args reply `0xFF`.
///
/// When AOF is enabled, every mutating command that runs to completion here is
/// appended to the log (plus a `DEL` for any key LRU-evicted as a side effect),
/// so the exact history can be replayed on restart.
fn apply_into(server: &Server, action: u8, key: &[u8], value: &[u8], ttl: u32, out: &mut Vec<u8>) {
    let now = now_secs();
    let mut cache = lock_or_recover!(server.cache.write());
    match action {
        // ---- strings ----
        ACT_SET => {
            let expires_at = if ttl > 0 { Some(now + ttl as u64) } else { None };
            cache.set(key.to_vec(), Value::Str(value.to_vec()), expires_at, now);
            out.push(RSP_OK);
        }
        ACT_GET => match cache.live_idx(key, now) {
            Some(idx) => match cache.value_ref(idx) {
                Value::Str(s) => {
                    server.hits.fetch_add(1, Ordering::Relaxed);
                    reply_bulk(out, s);
                }
                _ => out.push(RSP_ERROR), // WRONGTYPE
            },
            None => {
                server.misses.fetch_add(1, Ordering::Relaxed);
                out.push(RSP_MISSING);
            }
        },
        ACT_DEL => out.push(if cache.del(key, now) { RSP_OK } else { RSP_MISSING }),
        ACT_FLUSH => {
            cache.flush();
            out.push(RSP_OK);
        }
        ACT_TYPE => match cache.live_idx(key, now) {
            Some(idx) => reply_bulk(out, cache.value_ref(idx).type_name().as_bytes()),
            None => reply_bulk(out, b"none"),
        },

        // ---- hashes ----
        ACT_HSET => {
            let Some(args) = parse_args(value) else { return out.push(RSP_ERROR) };
            if args.len() != 2 {
                return out.push(RSP_ERROR);
            }
            let (field, val) = (args[0].to_vec(), args[1].to_vec());
            let idx = match cache.live_idx(key, now) {
                Some(i) => {
                    if !matches!(cache.value_ref(i), Value::Hash(_)) {
                        return out.push(RSP_ERROR);
                    }
                    i
                }
                None => cache.create(key.to_vec(), Value::Hash(HashMap::new()), None, now),
            };
            let old = cache.node_size(idx);
            let is_new = match cache.value_mut(idx) {
                Value::Hash(h) => h.insert(field, val).is_none(),
                _ => unreachable!(),
            };
            cache.commit(idx, old);
            reply_int(out, is_new as i64);
        }
        ACT_HGET => {
            let Some(args) = parse_args(value) else { return out.push(RSP_ERROR) };
            if args.len() != 1 {
                return out.push(RSP_ERROR);
            }
            match cache.live_idx(key, now) {
                Some(idx) => match cache.value_ref(idx) {
                    Value::Hash(h) => match h.get(args[0]) {
                        Some(v) => reply_bulk(out, v),
                        None => out.push(RSP_MISSING),
                    },
                    _ => out.push(RSP_ERROR),
                },
                None => out.push(RSP_MISSING),
            }
        }
        ACT_HDEL => {
            let Some(args) = parse_args(value) else { return out.push(RSP_ERROR) };
            if args.len() != 1 {
                return out.push(RSP_ERROR);
            }
            match cache.live_idx(key, now) {
                Some(idx) => {
                    if !matches!(cache.value_ref(idx), Value::Hash(_)) {
                        return out.push(RSP_ERROR);
                    }
                    let old = cache.node_size(idx);
                    let removed = match cache.value_mut(idx) {
                        Value::Hash(h) => h.remove(args[0]).is_some(),
                        _ => unreachable!(),
                    };
                    cache.commit(idx, old);
                    reply_int(out, removed as i64);
                }
                None => reply_int(out, 0),
            }
        }
        ACT_HGETALL => match cache.live_idx(key, now) {
            Some(idx) => match cache.value_ref(idx) {
                Value::Hash(h) => {
                    arr_header(out, (h.len() * 2) as u32);
                    for (k, v) in h.iter() {
                        arr_item(out, k);
                        arr_item(out, v);
                    }
                }
                _ => out.push(RSP_ERROR),
            },
            None => arr_header(out, 0),
        },
        ACT_HLEN => match cache.live_idx(key, now) {
            Some(idx) => match cache.value_ref(idx) {
                Value::Hash(h) => reply_int(out, h.len() as i64),
                _ => out.push(RSP_ERROR),
            },
            None => reply_int(out, 0),
        },

        // ---- lists ----
        ACT_LPUSH | ACT_RPUSH => {
            let Some(args) = parse_args(value) else { return out.push(RSP_ERROR) };
            if args.is_empty() {
                return out.push(RSP_ERROR);
            }
            let idx = match cache.live_idx(key, now) {
                Some(i) => {
                    if !matches!(cache.value_ref(i), Value::List(_)) {
                        return out.push(RSP_ERROR);
                    }
                    i
                }
                None => cache.create(key.to_vec(), Value::List(VecDeque::new()), None, now),
            };
            let old = cache.node_size(idx);
            let len = match cache.value_mut(idx) {
                Value::List(l) => {
                    for a in &args {
                        if action == ACT_LPUSH {
                            l.push_front(a.to_vec());
                        } else {
                            l.push_back(a.to_vec());
                        }
                    }
                    l.len()
                }
                _ => unreachable!(),
            };
            cache.commit(idx, old);
            reply_int(out, len as i64);
        }
        ACT_LPOP | ACT_RPOP => match cache.live_idx(key, now) {
            Some(idx) => {
                if !matches!(cache.value_ref(idx), Value::List(_)) {
                    return out.push(RSP_ERROR);
                }
                let old = cache.node_size(idx);
                let popped = match cache.value_mut(idx) {
                    Value::List(l) => {
                        if action == ACT_LPOP {
                            l.pop_front()
                        } else {
                            l.pop_back()
                        }
                    }
                    _ => unreachable!(),
                };
                match popped {
                    Some(v) => {
                        reply_bulk(out, &v);
                        cache.commit(idx, old); // drops the key if the list is now empty
                    }
                    None => out.push(RSP_MISSING),
                }
            }
            None => out.push(RSP_MISSING),
        },
        ACT_LLEN => match cache.live_idx(key, now) {
            Some(idx) => match cache.value_ref(idx) {
                Value::List(l) => reply_int(out, l.len() as i64),
                _ => out.push(RSP_ERROR),
            },
            None => reply_int(out, 0),
        },
        ACT_LRANGE => {
            if value.len() != 16 {
                return out.push(RSP_ERROR);
            }
            let start = i64::from_be_bytes(value[0..8].try_into().unwrap());
            let stop = i64::from_be_bytes(value[8..16].try_into().unwrap());
            match cache.live_idx(key, now) {
                Some(idx) => match cache.value_ref(idx) {
                    Value::List(l) => {
                        let n = l.len() as i64;
                        let s = if start < 0 { (n + start).max(0) } else { start.min(n) };
                        let e = if stop < 0 { n + stop } else { stop }.min(n - 1);
                        if s > e || s >= n {
                            arr_header(out, 0);
                        } else {
                            let count = (e - s + 1) as usize;
                            arr_header(out, count as u32);
                            for item in l.iter().skip(s as usize).take(count) {
                                arr_item(out, item);
                            }
                        }
                    }
                    _ => out.push(RSP_ERROR),
                },
                None => arr_header(out, 0),
            }
        }

        // ---- sets ----
        ACT_SADD | ACT_SREM => {
            let Some(args) = parse_args(value) else { return out.push(RSP_ERROR) };
            if args.is_empty() {
                return out.push(RSP_ERROR);
            }
            if action == ACT_SREM {
                match cache.live_idx(key, now) {
                    Some(idx) => {
                        if !matches!(cache.value_ref(idx), Value::Set(_)) {
                            return out.push(RSP_ERROR);
                        }
                        let old = cache.node_size(idx);
                        let removed = match cache.value_mut(idx) {
                            Value::Set(s) => args.iter().filter(|a| s.remove(**a)).count(),
                            _ => unreachable!(),
                        };
                        cache.commit(idx, old);
                        reply_int(out, removed as i64);
                    }
                    None => reply_int(out, 0),
                }
            } else {
                let idx = match cache.live_idx(key, now) {
                    Some(i) => {
                        if !matches!(cache.value_ref(i), Value::Set(_)) {
                            return out.push(RSP_ERROR);
                        }
                        i
                    }
                    None => cache.create(key.to_vec(), Value::Set(HashSet::new()), None, now),
                };
                let old = cache.node_size(idx);
                let added = match cache.value_mut(idx) {
                    Value::Set(s) => args.iter().filter(|a| s.insert(a.to_vec())).count(),
                    _ => unreachable!(),
                };
                cache.commit(idx, old);
                reply_int(out, added as i64);
            }
        }
        ACT_SISMEMBER => {
            let Some(args) = parse_args(value) else { return out.push(RSP_ERROR) };
            if args.len() != 1 {
                return out.push(RSP_ERROR);
            }
            match cache.live_idx(key, now) {
                Some(idx) => match cache.value_ref(idx) {
                    Value::Set(s) => reply_int(out, s.contains(args[0]) as i64),
                    _ => out.push(RSP_ERROR),
                },
                None => reply_int(out, 0),
            }
        }
        ACT_SMEMBERS => match cache.live_idx(key, now) {
            Some(idx) => match cache.value_ref(idx) {
                Value::Set(s) => {
                    arr_header(out, s.len() as u32);
                    for m in s.iter() {
                        arr_item(out, m);
                    }
                }
                _ => out.push(RSP_ERROR),
            },
            None => arr_header(out, 0),
        },
        ACT_SCARD => match cache.live_idx(key, now) {
            Some(idx) => match cache.value_ref(idx) {
                Value::Set(s) => reply_int(out, s.len() as i64),
                _ => out.push(RSP_ERROR),
            },
            None => reply_int(out, 0),
        },

        // ---- pub/sub (uses the subs registry, not the cache) ----
        ACT_PUBLISH => {
            drop(cache); // release the cache lock; publish only touches subs
            let mut subs = lock_or_recover!(server.subs.lock());
            if let Some(list) = subs.get_mut(key) {
                list.retain(|tx| tx.send(value.to_vec()).is_ok());
                if list.is_empty() {
                    subs.remove(key);
                }
            }
            out.push(RSP_OK);
            return; // cache lock already dropped — skip the AOF tail below
        }

        _ => out.push(RSP_ERROR), // unknown action byte
    }

    // --- AOF: persist this command, then any evictions it triggered. ---------
    // Ordering matters: the command is logged before the eviction deletes it
    // caused, so replay reproduces the same sequence. Read-only commands and the
    // `0xFF` error paths (which early-`return`ed above) are never logged.
    let mut aof_ok = true;
    match &server.aof {
        Some(aof) => {
            if is_mutating(action) {
                let frame = if action == ACT_SET {
                    // Store an absolute expiry so a restart doesn't reset the TTL.
                    let ttl_abs = if ttl > 0 { (now + ttl as u64) as u32 } else { 0 };
                    encode_frame(ACT_SET, key, value, ttl_abs)
                } else {
                    encode_frame(action, key, value, 0)
                };
                if !aof.log(frame) {
                    aof_ok = false;
                }
            }
            for k in cache.evicted.drain(..) {
                if !aof.log(encode_frame(ACT_DEL, &k, &[], 0)) {
                    aof_ok = false;
                }
            }
        }
        // AOF off: still drain eviction markers so they can't accumulate.
        None => cache.evicted.clear(),
    }
    if !aof_ok {
        out.clear();
        out.push(RSP_AOF_ERROR);
    }
}

/// Encode a full request frame (11-byte header + key + value); the inverse of
/// `decode_header`. Used to serialize an applied command for the AOF log. For a
/// `SET`, `ttl` carries the **absolute** expiry the replay path expects (0 = none).
fn encode_frame(action: u8, key: &[u8], value: &[u8], ttl: u32) -> Vec<u8> {
    let mut f = Vec::with_capacity(HEADER_LEN + key.len() + value.len());
    f.push(action);
    f.extend_from_slice(&(key.len() as u16).to_be_bytes());
    f.extend_from_slice(&(value.len() as u32).to_be_bytes());
    f.extend_from_slice(&ttl.to_be_bytes());
    f.extend_from_slice(key);
    f.extend_from_slice(value);
    f
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

/// The documentation page (setup, URI, clients, config) — also baked in.
const DOCS_HTML: &str = include_str!("docs.html");

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
    let method = parse_request_method(&req).unwrap_or_default();

    // Auth gate for data-bearing routes. `/` (the static shell) stays open so
    // the browser can load and prompt for a token — it exposes no cache data.
    // Credentials come from an `Authorization: Bearer` header (API clients,
    // Prometheus) or the HttpOnly session cookie set by `/login` (browser) —
    // never from the URL, so the token can't leak into logs/history/Referer.
    let authorized = server.auth.is_none() || {
        match http_token(&req) {
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
        // Documentation page — open, like `/`; it exposes no cache data.
        "/docs" => {
            let _ = write_http(&mut stream, 200, "text/html; charset=utf-8", DOCS_HTML.as_bytes()).await;
        }
        // Exchange a verified token for an HttpOnly session cookie. The token
        // is presented in the Authorization header (never the URL); on success
        // the browser stores the cookie and authenticates every later request
        // — fetch, WebSocket, and plain navigation — automatically.
        "/login" if method == "POST" && authorized => {
            let tok = http_token(&req).unwrap_or_default();
            let _ = write_http_session(&mut stream, &session_cookie(&tok, true)).await;
        }
        "/login" if method == "POST" => {
            let _ = write_http(&mut stream, 401, "text/plain", b"Unauthorized").await;
        }
        // Drop the session cookie.
        "/logout" if method == "POST" => {
            let _ = write_http_session(&mut stream, &session_cookie("", false)).await;
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
        // Trigger an on-demand AOF compaction (BGREWRITEAOF-style). Authorized.
        "/aof/rewrite" if method == "POST" && authorized => {
            let (code, msg): (u16, &[u8]) = match trigger_aof_rewrite(&server) {
                RewriteStatus::Started => (202, b"rewrite started\n"),
                RewriteStatus::AlreadyRunning => (409, b"rewrite already in progress\n"),
                RewriteStatus::TooSoon => (429, b"rewrite rate limited\n"),
                RewriteStatus::Disabled => (409, b"AOF disabled\n"),
            };
            let _ = write_http(&mut stream, code, "text/plain", msg).await;
        }
        "/aof/rewrite" if method == "POST" => {
            let _ = write_http(&mut stream, 401, "text/plain", b"Unauthorized").await;
        }
        _ => {
            let _ = write_http(&mut stream, 404, "text/plain", b"Not Found").await;
        }
    }
}

/// Extract an auth token from a request: an `Authorization: Bearer <t>` header
/// (API clients, Prometheus) or the `picodb_session` cookie set by `/login`
/// (browser). The token is deliberately never read from the URL, so it cannot
/// leak into access logs, browser history, or `Referer` headers.
fn http_token(req: &[u8]) -> Option<String> {
    if let Some(h) = header_value(req, "authorization") {
        if let Some(rest) = h.strip_prefix("Bearer ").or_else(|| h.strip_prefix("bearer ")) {
            return Some(rest.trim().to_string());
        }
    }
    cookie_value(req, "picodb_session")
}

/// Read a single named cookie from the `Cookie` request header.
fn cookie_value(req: &[u8], name: &str) -> Option<String> {
    let header = header_value(req, "cookie")?;
    let prefix = format!("{name}=");
    for pair in header.split(';') {
        if let Some(v) = pair.trim().strip_prefix(&prefix) {
            return Some(v.to_string());
        }
    }
    None
}

/// Build the `Set-Cookie` value for the session. `set = true` persists the
/// token for a day; `set = false` clears it (logout). Flags: `HttpOnly` keeps
/// it out of reach of JS/XSS, `SameSite=Strict` blocks cross-site (CSRF) sends.
/// (`Secure` is omitted so it works over plain HTTP; front with TLS in prod.)
fn session_cookie(token: &str, set: bool) -> String {
    if set {
        format!("picodb_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400")
    } else {
        "picodb_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0".to_string()
    }
}

/// Extract the request method (first token of the request line).
fn parse_request_method(req: &[u8]) -> Option<String> {
    let line_end = find_subslice(req, b"\r\n")?;
    let line = std::str::from_utf8(&req[..line_end]).ok()?;
    line.split(' ').next().map(str::to_string)
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
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
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

/// Write a 204 response carrying a `Set-Cookie` header (login / logout). No
/// body, so no `Content-Length` is needed.
async fn write_http_session(stream: &mut TcpStream, cookie: &str) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 204 No Content\r\n\
         Set-Cookie: {cookie}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).await?;
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

    s.push_str("# HELP picodb_aof_enabled Whether append-only persistence is enabled (1/0).\n");
    s.push_str("# TYPE picodb_aof_enabled gauge\n");
    match &server.aof {
        Some(aof) => {
            let size = aof.size.load(Ordering::Relaxed);
            let rewrites = aof.rewrites.load(Ordering::Relaxed);
            s.push_str("picodb_aof_enabled 1\n");
            s.push_str("# HELP picodb_aof_size_bytes Approximate current AOF size in bytes.\n");
            s.push_str("# TYPE picodb_aof_size_bytes gauge\n");
            s.push_str(&format!("picodb_aof_size_bytes {size}\n"));
            let healthy = aof.healthy.load(Ordering::Acquire);
            let write_errors = aof.write_errors.load(Ordering::Relaxed);
            s.push_str("# HELP picodb_aof_rewrites_total Completed AOF rewrites (compactions).\n");
            s.push_str("# TYPE picodb_aof_rewrites_total counter\n");
            s.push_str(&format!("picodb_aof_rewrites_total {rewrites}\n"));
            s.push_str("# HELP picodb_aof_healthy Whether the AOF writer thread is healthy (1/0).\n");
            s.push_str("# TYPE picodb_aof_healthy gauge\n");
            s.push_str(&format!("picodb_aof_healthy {}\n", healthy as u8));
            s.push_str("# HELP picodb_aof_write_errors_total Total AOF write errors.\n");
            s.push_str("# TYPE picodb_aof_write_errors_total counter\n");
            s.push_str(&format!("picodb_aof_write_errors_total {write_errors}\n"));
        }
        None => s.push_str("picodb_aof_enabled 0\n"),
    }

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
    let (aof_enabled, aof_size, aof_healthy) = match &server.aof {
        Some(a) => (true, a.size.load(Ordering::Relaxed), a.healthy.load(Ordering::Acquire)),
        None => (false, 0, true),
    };
    s.push_str(&format!("\"aof_enabled\":{aof_enabled},"));
    s.push_str(&format!("\"aof_size_bytes\":{aof_size},"));
    s.push_str(&format!("\"aof_healthy\":{},", aof_healthy as u8));
    s.push_str("\"keys\":[");
    for (i, (key, ktype, size, count, ttl)) in entries.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str("{\"key\":\"");
        json_escape_into(&mut s, key);
        s.push_str(&format!(
            "\",\"type\":\"{ktype}\",\"size\":{size},\"count\":{count},\"ttl\":"
        ));
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

/// Resolve the shared auth secret. Priority:
///   1. `PICODB_TOKEN`                    -> secret is the token verbatim
///   2. `PICODB_PASSWORD` (+ optional     -> secret is "username:password"
///      `PICODB_USERNAME`, default "default")
///   3. neither set                       -> auth disabled
/// Clients send this exact string in the AUTH frame / as the HTTP Bearer token.
/// The secret is never logged.
fn config_token() -> Option<Vec<u8>> {
    if let Ok(t) = env::var("PICODB_TOKEN") {
        if !t.is_empty() {
            return Some(t.into_bytes());
        }
    }
    if let Ok(pass) = env::var("PICODB_PASSWORD") {
        if !pass.is_empty() {
            let user = env::var("PICODB_USERNAME").unwrap_or_else(|_| "default".to_string());
            return Some(format!("{user}:{pass}").into_bytes());
        }
    }
    None
}

/// Address to bind both listeners to. Defaults to loopback (`127.0.0.1`) — the
/// security boundary. Set `PICODB_BIND=0.0.0.0` to expose on all interfaces
/// (only do this with `PICODB_TOKEN` set, and ideally TLS via a reverse proxy).
fn config_bind() -> String {
    env::var("PICODB_BIND").unwrap_or_else(|_| "127.0.0.1".to_string())
}

/// Parse a `u16` port from `var`, falling back to `default` when unset/invalid.
fn config_port(var: &str, default: u16) -> u16 {
    env::var(var).ok().and_then(|v| v.parse::<u16>().ok()).unwrap_or(default)
}

/// AOF log path. Unset/empty -> AOF disabled (pure in-memory, the default).
fn config_aof_path() -> Option<PathBuf> {
    env::var("PICODB_AOF_PATH").ok().filter(|p| !p.is_empty()).map(PathBuf::from)
}

/// Durability policy for the AOF writer (default `everysec`).
fn config_aof_fsync() -> Fsync {
    env::var("PICODB_AOF_FSYNC").map(|v| Fsync::parse(&v)).unwrap_or(Fsync::EverySec)
}

/// Minimum AOF size before an automatic rewrite is considered (default 64 MiB).
fn config_aof_rewrite_min() -> u64 {
    env::var("PICODB_AOF_REWRITE_MIN_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(64 * 1024 * 1024)
}

/// Minimum interval in seconds between manual rewrites (default 30). The
/// background auto-compaction task is unaffected by this limit.
fn config_aof_rewrite_min_interval() -> Duration {
    Duration::from_secs(
        env::var("PICODB_AOF_REWRITE_MIN_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30),
    )
}

/// Snapshot the live dataset and hand it to the writer thread for compaction.
/// Returns false if AOF is off or a rewrite is already in flight. The snapshot is
/// taken under the read lock, so it sits at a well-defined point in the log stream
/// (every command logged before this call is already reflected).
#[must_use]
enum RewriteStatus {
    Started,
    AlreadyRunning,
    TooSoon,
    Disabled,
}

fn trigger_aof_rewrite(server: &Server) -> RewriteStatus {
    let Some(aof) = server.aof.as_ref() else {
        return RewriteStatus::Disabled;
    };
    {
        let last = *aof.last_rewrite.lock().unwrap();
        if last.elapsed() < aof.rewrite_min_interval {
            return RewriteStatus::TooSoon;
        }
    }
    if aof.rewriting.swap(true, Ordering::AcqRel) {
        return RewriteStatus::AlreadyRunning;
    }
    // Stamp the start time before the rewrite has a chance to finish, so the
    // rate-limit check above catches back-to-back callers during the rewrite.
    *aof.last_rewrite.lock().unwrap() = Instant::now();
    let frames = {
        let cache = lock_or_recover!(server.cache.read());
        cache.dump_frames(now_secs())
    };
    if aof.tx.send(AofMsg::Rewrite(frames)).is_err() {
        aof.rewriting.store(false, Ordering::Release);
        return RewriteStatus::Disabled; // writer is dead
    }
    RewriteStatus::Started
}

/// Resolve when the process is asked to stop (Ctrl-C / SIGTERM). Used to flush
/// the AOF durably before exit, so a clean restart never loses buffered writes.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).ok();
        tokio::select! {
            _ = ctrl_c => {}
            _ = async {
                match term.as_mut() {
                    Some(t) => { t.recv().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}

/// Background task: auto-compact the AOF when it grows too large. Fires a rewrite
/// once the log is both ≥ `min_bytes` and ≥ 2× its size after the last rewrite
/// (Redis's default policy). Checks every 10s; a no-op when AOF is disabled.
async fn aof_maintenance(server: Arc<Server>, min_bytes: u64) {
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    interval.tick().await; // discard the immediate first tick
    let mut base: u64 = 0; // AOF size after the last rewrite (0 => compact once past min)
    let mut pending = false;
    loop {
        interval.tick().await;
        let Some(aof) = server.aof.as_ref() else {
            return;
        };
        let size = aof.size.load(Ordering::Relaxed);
        if pending && !aof.rewriting.load(Ordering::Acquire) {
            base = size; // rewrite finished: adopt the compacted size as the baseline
            pending = false;
        }
        if !pending && size >= min_bytes && size >= base.saturating_mul(2) {
            if matches!(trigger_aof_rewrite(&server), RewriteStatus::Started) {
                pending = true;
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cap = config_cap();
    let auth = config_token();
    let bind = config_bind();
    let port_engine = config_port("PICODB_ENGINE_PORT", DEFAULT_PORT_ENGINE);
    let port_http = config_port("PICODB_HTTP_PORT", DEFAULT_PORT_HTTP);
    let aof_path = config_aof_path();
    let aof_fsync = config_aof_fsync();
    let aof_rewrite_min = config_aof_rewrite_min();
    let auth_enabled = auth.is_some();
    let auth_status = if auth_enabled {
        "enabled"
    } else {
        "DISABLED (set PICODB_TOKEN)"
    };

    // Single shared state. `std::sync::RwLock` (not tokio's async lock) is
    // deliberate: critical sections are pure in-memory ops with no `.await`
    // inside, so a blocking lock is faster and never starves the runtime.
    let mut server = Server::new(cap, auth);

    // Persistence: replay the log to rebuild memory, THEN install the writer so
    // the replayed commands aren't re-logged. Done before serving any traffic.
    let aof_status = if let Some(path) = &aof_path {
        // Reject named pipes (FIFOs) as AOF paths: opening them for append blocks
        // forever because the writer thread's BufWriter never sees EOF on the read
        // side, and there's no reader for the write side.  Regular files, symlinks
        // to regular files, and character devices (e.g. /dev/null) are fine.
        if path.exists() {
            let meta = match std::fs::metadata(path) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("PicoDB: cannot stat AOF path '{}': {e}", path.display());
                    std::process::exit(1);
                }
            };
            #[cfg(unix)]
            if meta.file_type().is_fifo() {
                eprintln!("PicoDB: AOF path '{}' is a FIFO (named pipe), refusing", path.display());
                std::process::exit(1);
            }
        }
        match replay_aof(&server, path) {
            Ok(n) => eprintln!("PicoDB: replayed {n} commands from AOF {}", path.display()),
            Err(e) => {
                eprintln!("PicoDB: cannot read AOF {}: {e}", path.display());
                std::process::exit(1);
            }
        }
        match spawn_aof_writer(path.clone(), aof_fsync, config_aof_rewrite_min_interval()) {
            Ok(aof) => server.aof = Some(aof),
            Err(e) => {
                eprintln!("PicoDB: cannot open AOF {} for writing: {e}", path.display());
                std::process::exit(1);
            }
        }
        let policy = match aof_fsync {
            Fsync::Always => "always",
            Fsync::EverySec => "everysec",
            Fsync::No => "no",
        };
        format!("{} (fsync {policy})", path.display())
    } else {
        "disabled".to_string()
    };

    let server = Arc::new(server);

    let engine = TcpListener::bind((bind.as_str(), port_engine)).await?;
    let http = TcpListener::bind((bind.as_str(), port_http)).await?;

    // Loud warning when exposed on a non-loopback address without auth.
    if bind != "127.0.0.1" && bind != "localhost" && !auth_enabled {
        eprintln!("WARNING: bound to {bind} with auth DISABLED — anyone who can reach this host has full access. Set PICODB_TOKEN.");
    }

    eprintln!(
        "PicoDB up — engine {bind}:{port_engine} (binary) · dashboard http://{bind}:{port_http}/ · RAM cap {} MiB · auth: {auth_status} · AOF: {aof_status}",
        cap / (1024 * 1024)
    );

    // Background AOF compaction + durable flush on graceful shutdown (both
    // no-ops when AOF is disabled).
    if aof_path.is_some() {
        tokio::spawn(aof_maintenance(Arc::clone(&server), aof_rewrite_min));

        let shutdown_srv = Arc::clone(&server);
        tokio::spawn(async move {
            shutdown_signal().await;
            if let Some(aof) = shutdown_srv.aof.as_ref() {
                aof.flush_blocking();
            }
            std::process::exit(0);
        });
    }

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
