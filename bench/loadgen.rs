// Fair native load generator for PicoDB — std::net blocking sockets + threads.
// No external crates, compiled with `rustc -O`. Mirrors redis-benchmark style.
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Instant;

const ENG: &str = "127.0.0.1:7120";

fn frame(action: u8, key: &[u8], val: &[u8], ttl: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(11 + key.len() + val.len());
    b.push(action);
    b.extend_from_slice(&(key.len() as u16).to_be_bytes());
    b.extend_from_slice(&(val.len() as u32).to_be_bytes());
    b.extend_from_slice(&ttl.to_be_bytes());
    b.extend_from_slice(key);
    b.extend_from_slice(val);
    b
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let conns: usize = args.get(1).map(|s| s.parse().unwrap()).unwrap_or(4);
    let total: u64 = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(2_000_000);
    let batch: usize = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(1000);

    // ---- Latency: sequential single-op GET on one connection ----
    {
        let mut s = TcpStream::connect(ENG).unwrap();
        s.set_nodelay(true).unwrap();
        s.write_all(&frame(1, b"k", b"v", 0)).unwrap();
        let mut r = [0u8; 16];
        s.read(&mut r).unwrap();
        let n = 100_000u64;
        let g = frame(2, b"k", b"", 0);
        let t0 = Instant::now();
        for _ in 0..n {
            s.write_all(&g).unwrap();
            let _ = s.read(&mut r).unwrap();
        }
        let dt = t0.elapsed().as_secs_f64();
        println!("[PicoDB] sequential GET : {:>10.0} ops/s | avg RTT {:.2} us",
                 n as f64 / dt, dt / n as f64 * 1e6);
    }

    // ---- Throughput: pipelined SET across N connections ----
    let done = Arc::new(AtomicU64::new(0));
    let per = total / conns as u64;
    let payload = vec![b'x'; 64];
    let mut frames = Vec::new();
    for i in 0..batch { frames.extend_from_slice(&frame(1, format!("key{:08}", i).as_bytes(), &payload, 0)); }
    let frames = Arc::new(frames);

    let t0 = Instant::now();
    let mut handles = Vec::new();
    for _ in 0..conns {
        let frames = Arc::clone(&frames);
        let done = Arc::clone(&done);
        handles.push(thread::spawn(move || {
            let mut s = TcpStream::connect(ENG).unwrap();
            s.set_nodelay(true).unwrap();
            let mut ack = vec![0u8; 65536];
            let mut sent = 0u64;
            while sent < per {
                s.write_all(&frames).unwrap();
                let mut got = 0usize;
                while got < batch {
                    got += s.read(&mut ack).unwrap();
                }
                sent += batch as u64;
                done.fetch_add(batch as u64, Ordering::Relaxed);
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
    let dt = t0.elapsed().as_secs_f64();
    println!("[PicoDB] pipelined SET  : {:>10.0} ops/s ({} conn, batch {})",
             done.load(Ordering::Relaxed) as f64 / dt, conns, batch);
}
