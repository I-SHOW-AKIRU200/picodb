// Minimal PicoDB client for Node.js (raw binary protocol, port 7120).
// Zero dependencies — just the built-in `net` module.
//
// Usage:
//   const { PicoDB } = require("./client");
//   const db = await PicoDB.connect("picodb://default:s3cret@127.0.0.1:7120");
//   await db.set("user:1", "alice", 3600);
//   console.log((await db.get("user:1")).toString()); // "alice"
//   db.close();

const net = require("net");

const SET = 1, GET = 2, DEL = 3, FLUSH = 4, PUBLISH = 6, AUTH = 7, TYPE = 8;
const HSET = 0x10, HGET = 0x11, HDEL = 0x12, HGETALL = 0x13, HLEN = 0x14;
const LPUSH = 0x20, RPUSH = 0x21, LPOP = 0x22, RPOP = 0x23, LRANGE = 0x24, LLEN = 0x25;
const SADD = 0x30, SREM = 0x31, SMEMBERS = 0x32, SISMEMBER = 0x33, SCARD = 0x34;
const OK = 0x00, MISSING = 0x44;

// Pack args as [len u32 BE][bytes]… for compound commands.
function packArgs(items) {
  return Buffer.concat(items.map((x) => {
    const b = Buffer.isBuffer(x) ? x : Buffer.from(String(x));
    const h = Buffer.alloc(4); h.writeUInt32BE(b.length, 0);
    return Buffer.concat([h, b]);
  }));
}

function frame(action, key = Buffer.alloc(0), value = Buffer.alloc(0), ttl = 0) {
  key = Buffer.isBuffer(key) ? key : Buffer.from(key);
  value = Buffer.isBuffer(value) ? value : Buffer.from(value);
  const head = Buffer.alloc(11);
  head.writeUInt8(action, 0);
  head.writeUInt16BE(key.length, 1);
  head.writeUInt32BE(value.length, 3);
  head.writeUInt32BE(ttl, 7);
  return Buffer.concat([head, key, value]);
}

class PicoDB {
  constructor(sock) {
    this.sock = sock;
    this.buf = Buffer.alloc(0);
    this.waiters = [];
    sock.on("data", (d) => { this.buf = Buffer.concat([this.buf, d]); this._pump(); });
    sock.on("error", () => this._fail(new Error("socket error")));
    sock.on("close", () => this._fail(new Error("connection closed")));
  }

  // Read exactly n bytes (resolves when enough have buffered).
  _read(n) {
    return new Promise((resolve, reject) => {
      this.waiters.push({ n, resolve, reject });
      this._pump();
    });
  }
  _pump() {
    while (this.waiters.length && this.buf.length >= this.waiters[0].n) {
      const w = this.waiters.shift();
      const out = this.buf.subarray(0, w.n);
      this.buf = this.buf.subarray(w.n);
      w.resolve(out);
    }
  }
  _fail(err) { while (this.waiters.length) this.waiters.shift().reject(err); }

  async _status() { return (await this._read(1))[0]; }

  static connect(uri) {
    const u = new URL(uri);
    if (u.protocol !== "picodb:") throw new Error("expected picodb:// URI");
    const host = u.hostname || "127.0.0.1";
    const port = parseInt(u.port || "7120", 10);
    const user = decodeURIComponent(u.username || "");
    const pass = decodeURIComponent(u.password || "");
    const token = user ? `${user}:${pass}` : (pass || null);
    return new Promise((resolve, reject) => {
      const sock = net.connect({ host, port }, async () => {
        sock.setNoDelay(true);
        const db = new PicoDB(sock);
        try {
          if (token) {
            sock.write(frame(AUTH, token));
            if ((await db._status()) !== OK) throw new Error("authentication failed");
          }
          resolve(db);
        } catch (e) { reject(e); }
      });
      sock.on("error", reject);
    });
  }

  async set(key, value, ttl = 0) { this.sock.write(frame(SET, key, value, ttl)); return (await this._status()) === OK; }

  async get(key) {
    this.sock.write(frame(GET, key));
    const st = await this._status();
    if (st === MISSING) return null;
    if (st !== OK) throw new Error("server error");
    const len = (await this._read(4)).readUInt32BE(0); // length-prefixed value
    return await this._read(len);
  }

  async delete(key) { this.sock.write(frame(DEL, key)); return (await this._status()) === OK; }
  async flush()      { this.sock.write(frame(FLUSH));   return (await this._status()) === OK; }
  async publish(ch, msg) { this.sock.write(frame(PUBLISH, ch, msg)); return (await this._status()) === OK; }
  async type(key)    { this.sock.write(frame(TYPE, key)); return (await this._readBulk()).toString(); }

  // reply readers
  async _readInt() { if ((await this._status()) !== OK) throw new Error("server error"); return Number((await this._read(8)).readBigInt64BE(0)); }
  async _readBulk() { const st = await this._status(); if (st === MISSING) return null; if (st !== OK) throw new Error("server error"); const len = (await this._read(4)).readUInt32BE(0); return await this._read(len); }
  async _readArray() { if ((await this._status()) !== OK) throw new Error("server error"); const n = (await this._read(4)).readUInt32BE(0); const out = []; for (let i = 0; i < n; i++) { const len = (await this._read(4)).readUInt32BE(0); out.push(await this._read(len)); } return out; }

  // hashes
  async hset(key, field, value) { this.sock.write(frame(HSET, key, packArgs([field, value]))); return this._readInt(); }
  async hget(key, field) { this.sock.write(frame(HGET, key, packArgs([field]))); return this._readBulk(); }
  async hdel(key, field) { this.sock.write(frame(HDEL, key, packArgs([field]))); return this._readInt(); }
  async hgetall(key) { this.sock.write(frame(HGETALL, key)); const f = await this._readArray(); const o = {}; for (let i = 0; i < f.length; i += 2) o[f[i].toString()] = f[i + 1]; return o; }
  async hlen(key) { this.sock.write(frame(HLEN, key)); return this._readInt(); }

  // lists
  async lpush(key, ...items) { this.sock.write(frame(LPUSH, key, packArgs(items))); return this._readInt(); }
  async rpush(key, ...items) { this.sock.write(frame(RPUSH, key, packArgs(items))); return this._readInt(); }
  async lpop(key) { this.sock.write(frame(LPOP, key)); return this._readBulk(); }
  async rpop(key) { this.sock.write(frame(RPOP, key)); return this._readBulk(); }
  async lrange(key, start, stop) { const b = Buffer.alloc(16); b.writeBigInt64BE(BigInt(start), 0); b.writeBigInt64BE(BigInt(stop), 8); this.sock.write(frame(LRANGE, key, b)); return this._readArray(); }
  async llen(key) { this.sock.write(frame(LLEN, key)); return this._readInt(); }

  // sets
  async sadd(key, ...members) { this.sock.write(frame(SADD, key, packArgs(members))); return this._readInt(); }
  async srem(key, ...members) { this.sock.write(frame(SREM, key, packArgs(members))); return this._readInt(); }
  async smembers(key) { this.sock.write(frame(SMEMBERS, key)); return this._readArray(); }
  async sismember(key, member) { this.sock.write(frame(SISMEMBER, key, packArgs([member]))); return (await this._readInt()) === 1; }
  async scard(key) { this.sock.write(frame(SCARD, key)); return this._readInt(); }

  close() { this.sock.end(); }
}

module.exports = { PicoDB };

if (require.main === module) {
  (async () => {
    const uri = process.argv[2] || process.env.PICODB_URI || "picodb://127.0.0.1:7120";
    const db = await PicoDB.connect(uri);
    console.log("connected:", uri);
    await db.set("greeting", "hello from node", 60);
    console.log("get greeting ->", (await db.get("greeting")).toString());
    console.log("get missing  ->", await db.get("nope"));
    console.log("delete       ->", await db.delete("greeting"));
    db.close();
  })().catch((e) => { console.error(e); process.exit(1); });
}
