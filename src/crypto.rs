//! Aléa et hachage : jetons opaques, codes, étiquettes de maison.
//!
//! Les jetons (sessions, invitations) portent 256 bits d'aléa : un SHA-256 simple suffit à
//! les ranger en base. Les codes courts (e-mail, rattachement) vivent quelques minutes et
//! sont limités en essais.

use agendo_access_protocol::api::{ENROLLMENT_CODE_ALPHABET, ENROLLMENT_CODE_LEN, HOUSE_LABEL_ALPHABET, HOUSE_LABEL_LEN};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};

/// Jeton opaque : 32 octets aléatoires en base64url.
pub fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<32>())
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

/// Empreinte rangée en base à la place d'un secret.
pub fn hash(secret: &str) -> Vec<u8> {
    Sha256::digest(secret.as_bytes()).to_vec()
}

fn pick(alphabet: &str, len: usize) -> String {
    let alphabet = alphabet.as_bytes();
    let mut rng = rand::rng();
    (0..len).map(|_| alphabet[rng.random_range(0..alphabet.len())] as char).collect()
}

/// Code de connexion par e-mail : 6 chiffres.
pub fn six_digit_code() -> String {
    pick("0123456789", 6)
}

/// Code de rattachement d'une maison, sans caractère ambigu.
pub fn enrollment_code() -> String {
    pick(ENROLLMENT_CODE_ALPHABET, ENROLLMENT_CODE_LEN)
}

/// Étiquette de maison : 16 caractères base32 minuscules.
pub fn house_label() -> String {
    pick(HOUSE_LABEL_ALPHABET, HOUSE_LABEL_LEN)
}

#[cfg(test)]
mod tests {
    use agendo_access_protocol::api::{is_house_label, normalize_enrollment_code};

    use super::*;

    #[test]
    fn random_tokens_are_distinct_base64url() {
        let (a, b) = (random_token(), random_token());
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
        assert!(a.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'));
    }

    #[test]
    fn hash_is_sha256() {
        assert_eq!(hash("").len(), 32);
        assert_eq!(hash("abc")[..4], [0xba, 0x78, 0x16, 0xbf]);
    }

    #[test]
    fn codes_and_labels_have_their_shape() {
        for _ in 0..200 {
            let code = six_digit_code();
            assert!(code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()), "{code}");
            let enrollment = enrollment_code();
            assert_eq!(normalize_enrollment_code(&enrollment).as_deref(), Some(enrollment.as_str()));
            assert!(is_house_label(&house_label()));
        }
    }
}
