use rand::Rng;

/// Generate `len` random bytes and return them as a hex-encoded string (length = `len * 2`).
pub fn rand_hex(len: usize) -> String {
    let mut buf = vec![0u8; len];
    rand::rng().fill(&mut buf[..]);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rand_hex_length() {
        for len in [0, 1, 8, 16, 32] {
            assert_eq!(rand_hex(len).len(), len * 2);
        }
    }

    #[test]
    fn rand_hex_valid_hex() {
        let s = rand_hex(32);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
