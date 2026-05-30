//! Fixed-width hex parsing for fail-closed store/index sidecars (§10).

use crate::MnemeError;

/// Parse exactly 64 ASCII hex digits into 32 bytes; rejects multibyte UTF-8 keys (A-DB).
pub fn decode_hex32(hex_str: &str) -> Result<[u8; 32], MnemeError> {
    let bytes = hex_str.as_bytes();
    if bytes.len() != 64 {
        return Err(MnemeError::SchemaDrift);
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        *slot = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(out)
}

fn nibble(c: u8) -> Result<u8, MnemeError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(MnemeError::SchemaDrift),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_hex32_rejects_multibyte_utf8_key() {
        let key = format!("\u{20AC}{}", "a".repeat(61));
        assert_eq!(key.len(), 64);
        assert_eq!(decode_hex32(&key).unwrap_err(), MnemeError::SchemaDrift);
    }
}
