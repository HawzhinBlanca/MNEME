//! Fixed-width hex parsing for fail-closed store/index sidecars (§10).

use crate::MnemeError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HexDecodeFailure {
    Length,
    Digit,
}

/// Parse exactly 64 ASCII hex digits into 32 bytes; rejects multibyte UTF-8 keys (A-DB).
pub fn decode_hex32(hex_str: &str) -> Result<[u8; 32], MnemeError> {
    let bytes = hex_str.as_bytes();
    if bytes.len() != 64 {
        return Err(hex_length_error());
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
        _ => Err(hex_digit_error()),
    }
}

fn hex_decode_failure_to_mneme(failure: HexDecodeFailure) -> MnemeError {
    match failure {
        HexDecodeFailure::Length | HexDecodeFailure::Digit => MnemeError::SchemaDrift,
    }
}

fn hex_length_error() -> MnemeError {
    hex_decode_failure_to_mneme(HexDecodeFailure::Length)
}

fn hex_digit_error() -> MnemeError {
    hex_decode_failure_to_mneme(HexDecodeFailure::Digit)
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

    #[test]
    fn hex_decode_failures_are_classified_not_schema_drift_collapsed() {
        let source = include_str!("hex.rs");
        let direct_return = ["return Err(", "MnemeError::SchemaDrift", ")"].concat();
        let direct_err = ["Err(", "MnemeError::SchemaDrift", ")"].concat();

        let (_, after_decode) = source
            .split_once("pub fn decode_hex32(")
            .expect("hex parser should contain decode_hex32");
        let (decode_section, after_decode) = after_decode
            .split_once("fn nibble(")
            .expect("hex parser should contain nibble after decode_hex32");
        let (nibble_section, _) = after_decode
            .split_once("#[cfg(test)]")
            .expect("hex parser should contain tests after nibble");

        assert!(
            !decode_section.contains(&direct_return),
            "decode_hex32 length checks should route through a named classifier"
        );
        assert!(
            !nibble_section.contains(&direct_err),
            "nibble digit checks should route through a named classifier"
        );

        for required in [
            "enum HexDecodeFailure",
            "fn hex_decode_failure_to_mneme(",
            "fn hex_length_error(",
            "fn hex_digit_error(",
            "HexDecodeFailure::Length",
            "HexDecodeFailure::Digit",
        ] {
            assert!(
                source.contains(required),
                "hex parser failure classification should include `{required}`"
            );
        }
    }

    #[test]
    fn hex_decode_failure_classifier_preserves_schema_failures() {
        for failure in [HexDecodeFailure::Length, HexDecodeFailure::Digit] {
            assert_eq!(
                hex_decode_failure_to_mneme(failure),
                MnemeError::SchemaDrift
            );
        }
    }
}
