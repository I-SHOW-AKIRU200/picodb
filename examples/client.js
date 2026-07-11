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

const SET = 1, GET = 2, DEL = 3, FLUSH = 4, PUBLISH = 6, AUTH = 7;
const OK = 0x00, MISSING = 0x44;

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
