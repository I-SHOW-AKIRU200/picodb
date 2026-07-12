#!/usr/bin/env python3
"""Minimal PicoDB client for the raw binary protocol (port 7120).

Connect with a URI:  picodb://[user:password@]host[:port]
  - the part before '@' (user:password, or just :password) is the auth secret
  - it must match the server's PICODB_TOKEN, or PICODB_USERNAME/PICODB_PASSWORD

Usage:
    from client import PicoDB
    db = PicoDB.from_uri("picodb://default:s3cret@127.0.0.1:7120")
    db.set("user:1", "alice", ttl=3600)
    print(db.get("user:1"))     # b'alice'
    db.delete("user:1")
"""
import socket
import struct
from urllib.parse import urlsplit, unquote

# Action bytes
SET, GET, DEL, FLUSH, SUBSCRIBE, PUBLISH, AUTH, TYPE = 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
HSET, HGET, HDEL, HGETALL, HLEN = 0x10, 0x11, 0x12, 0x13, 0x14
LPUSH, RPUSH, LPOP, RPOP, LRANGE, LLEN = 0x20, 0x21, 0x22, 0x23, 0x24, 0x25
SADD, SREM, SMEMBERS, SISMEMBER, SCARD = 0x30, 0x31, 0x32, 0x33, 0x34
# Response status bytes
OK, MISSING, AUTH_FAIL, ERROR = 0x00, 0x44, 0x41, 0xFF


def _pack_args(items):
    """Pack args as [len u32 BE][bytes]… for compound commands."""
    out = b""
    for x in items:
        if isinstance(x, str):
            x = x.encode()
        out += struct.pack(">I", len(x)) + bytes(x)
    return out


class PicoDBError(Exception):
    pass


class PicoDB:
    def __init__(self, host="127.0.0.1", port=7120, token=None, timeout=5.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if token:
            self._authenticate(token)

    # --- construction -------------------------------------------------------
    @classmethod
    def from_uri(cls, uri, timeout=5.0):
        u = urlsplit(uri)
        if u.scheme != "picodb":
            raise PicoDBError(f"expected picodb:// URI, got {u.scheme!r}")
        # auth secret = "user:password" (or just "password" if no user given)
        token = None
        if u.username is not None or u.password is not None:
            user = unquote(u.username or "")
            pw = unquote(u.password or "")
            token = f"{user}:{pw}" if user else pw
        return cls(host=u.hostname or "127.0.0.1", port=u.port or 7120,
                   token=token, timeout=timeout)

    # --- low-level framing --------------------------------------------------
    @staticmethod
    def _frame(action, key=b"", value=b"", ttl=0):
        if isinstance(key, str): key = key.encode()
        if isinstance(value, str): value = value.encode()
        # [action:1][key len:2 BE][value len:4 BE][ttl:4 BE][key][value]
        return struct.pack(">BHII", action, len(key), len(value), ttl) + key + value

    def _recvn(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise PicoDBError("connection closed by server")
            buf += chunk
        return buf

    def _status(self):
        return self._recvn(1)[0]

    # --- commands -----------------------------------------------------------
    def _authenticate(self, token):
        self.sock.sendall(self._frame(AUTH, key=token))
        if self._status() != OK:
            raise PicoDBError("authentication failed (bad token / password)")

    def set(self, key, value, ttl=0):
        """Store key=value with optional TTL in seconds (0 = no expiry)."""
        self.sock.sendall(self._frame(SET, key, value, ttl))
        return self._status() == OK

    def get(self, key):
        """Return value bytes, or None if the key is missing/expired."""
        self.sock.sendall(self._frame(GET, key))
        st = self._status()
        if st == MISSING:
            return None
        if st == AUTH_FAIL:
            raise PicoDBError("not authenticated")
        if st != OK:
            raise PicoDBError("server error")
        (length,) = struct.unpack(">I", self._recvn(4))   # length-prefixed value
        return self._recvn(length)

    def delete(self, key):
        """Delete a key. Returns True if it existed."""
        self.sock.sendall(self._frame(DEL, key))
        return self._status() == OK

    def flush(self):
        """Wipe all keys."""
        self.sock.sendall(self._frame(FLUSH))
        return self._status() == OK

    def type(self, key):
        """Return the value type: 'string' | 'hash' | 'list' | 'set' | 'none'."""
        self.sock.sendall(self._frame(TYPE, key))
        return self._read_bulk().decode()

    # --- reply readers for the typed commands -------------------------------
    def _read_int(self):
        if self._status() != OK:
            raise PicoDBError("server error")
        return struct.unpack(">q", self._recvn(8))[0]

    def _read_bulk(self):
        st = self._status()
        if st == MISSING:
            return None
        if st != OK:
            raise PicoDBError("server error")
        (length,) = struct.unpack(">I", self._recvn(4))
        return self._recvn(length)

    def _read_array(self):
        if self._status() != OK:
            raise PicoDBError("server error")
        (count,) = struct.unpack(">I", self._recvn(4))
        items = []
        for _ in range(count):
            (length,) = struct.unpack(">I", self._recvn(4))
            items.append(self._recvn(length))
        return items

    # --- hashes -------------------------------------------------------------
    def hset(self, key, field, value):
        self.sock.sendall(self._frame(HSET, key, _pack_args([field, value])))
        return self._read_int()

    def hget(self, key, field):
        self.sock.sendall(self._frame(HGET, key, _pack_args([field])))
        return self._read_bulk()

    def hdel(self, key, field):
        self.sock.sendall(self._frame(HDEL, key, _pack_args([field])))
        return self._read_int()

    def hgetall(self, key):
        self.sock.sendall(self._frame(HGETALL, key))
        flat = self._read_array()
        return {flat[i]: flat[i + 1] for i in range(0, len(flat), 2)}

    def hlen(self, key):
        self.sock.sendall(self._frame(HLEN, key))
        return self._read_int()

    # --- lists --------------------------------------------------------------
    def lpush(self, key, *items):
        self.sock.sendall(self._frame(LPUSH, key, _pack_args(items)))
        return self._read_int()

    def rpush(self, key, *items):
        self.sock.sendall(self._frame(RPUSH, key, _pack_args(items)))
        return self._read_int()

    def lpop(self, key):
        self.sock.sendall(self._frame(LPOP, key))
        return self._read_bulk()

    def rpop(self, key):
        self.sock.sendall(self._frame(RPOP, key))
        return self._read_bulk()

    def lrange(self, key, start, stop):
        self.sock.sendall(self._frame(LRANGE, key, struct.pack(">qq", start, stop)))
        return self._read_array()

    def llen(self, key):
        self.sock.sendall(self._frame(LLEN, key))
        return self._read_int()

    # --- sets ---------------------------------------------------------------
    def sadd(self, key, *members):
        self.sock.sendall(self._frame(SADD, key, _pack_args(members)))
        return self._read_int()

    def srem(self, key, *members):
        self.sock.sendall(self._frame(SREM, key, _pack_args(members)))
        return self._read_int()

    def smembers(self, key):
        self.sock.sendall(self._frame(SMEMBERS, key))
        return set(self._read_array())

    def sismember(self, key, member):
        self.sock.sendall(self._frame(SISMEMBER, key, _pack_args([member])))
        return self._read_int() == 1

    def scard(self, key):
        self.sock.sendall(self._frame(SCARD, key))
        return self._read_int()

    def publish(self, channel, message):
        """Publish a message to a channel."""
        self.sock.sendall(self._frame(PUBLISH, channel, message))
        return self._status() == OK

    def subscribe(self, channel):
        """Subscribe; yields message payloads as they arrive (blocking generator)."""
        self.sock.sendall(self._frame(SUBSCRIBE, channel))
        if self._status() != OK:
            raise PicoDBError("subscribe rejected")
        while True:
            if self._status() != OK:
                break
            (length,) = struct.unpack(">I", self._recvn(4))
            yield self._recvn(length)

    def close(self):
        try: self.sock.close()
        except OSError: pass


if __name__ == "__main__":
    import os, sys
    uri = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("PICODB_URI", "picodb://127.0.0.1:7120")
    db = PicoDB.from_uri(uri)
    print("connected:", uri)
    db.set("greeting", "hello from python", ttl=60)
    print("get greeting ->", db.get("greeting"))
    print("get missing  ->", db.get("does-not-exist"))
    print("delete       ->", db.delete("greeting"))
    db.close()
