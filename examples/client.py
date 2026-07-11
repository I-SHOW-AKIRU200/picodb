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
SET, GET, DEL, FLUSH, SUBSCRIBE, PUBLISH, AUTH = 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
# Response status bytes
OK, MISSING, AUTH_FAIL, ERROR = 0x00, 0x44, 0x41, 0xFF


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
