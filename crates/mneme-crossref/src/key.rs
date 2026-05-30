use blake3::Hasher;

pub fn logical_key_hash(namespace: &str, name: &str) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"MNEME-key-v1\x00");
    h.update(namespace.as_bytes());
    h.update(&[0]);
    h.update(name.as_bytes());
    *h.finalize().as_bytes()
}
