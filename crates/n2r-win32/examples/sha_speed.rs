//! Throughput of the two SHA-256 implementations on this machine.
use sha2::Digest;
use std::time::Instant;

fn main() {
    let data = vec![0x5au8; 256 * 1024 * 1024];
    for chunk in [4096usize, 65536, 1 << 20] {
        let started = Instant::now();
        let mut native = n2r_win32::sha256_native::Sha256::new().unwrap();
        for part in data.chunks(chunk) {
            native.update(part).unwrap();
        }
        let a = native.finish().unwrap();
        let native_seconds = started.elapsed().as_secs_f64();
        let started = Instant::now();
        let mut rust = sha2::Sha256::new();
        for part in data.chunks(chunk) {
            rust.update(part);
        }
        let b: [u8; 32] = rust.finalize().into();
        let rust_seconds = started.elapsed().as_secs_f64();
        assert_eq!(a, b);
        println!(
            "chunk {chunk:>8}: Windows CNG {:.0} MB/s, sha2 crate {:.0} MB/s",
            256.0 / native_seconds,
            256.0 / rust_seconds
        );
    }
    let started = Instant::now();
    for _ in 0..2000 {
        let hash = n2r_win32::sha256_native::Sha256::new().unwrap();
        let _ = hash.finish().unwrap();
    }
    println!("2000 CNG hash objects opened and finished in {:.2} s", started.elapsed().as_secs_f64());
}
