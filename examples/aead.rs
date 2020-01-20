use core::num::NonZeroU32;
use ring::aead::{Aad, BoundKey, Nonce, NONCE_LEN};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use ring::{aead, error};

// aead is described in details here https://tools.ietf.org/html/rfc5116

struct OneNonceSequence(Option<aead::Nonce>);

impl OneNonceSequence {
    fn new(nonce: aead::Nonce) -> Self {
        Self(Some(nonce))
    }
}

impl aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<aead::Nonce, error::Unspecified> {
        self.0.take().ok_or(error::Unspecified)
    }
}

fn main() {
    let text = "content to encrypt";
    let mut in_out = text.as_bytes().to_vec();
    println!("data {:?}", &in_out);

    // generate nonce
    let rand_gen = SystemRandom::new();
    let mut rand_vec = [0u8; NONCE_LEN];
    rand_gen.fill(&mut rand_vec).unwrap();

    // encrypt
    let mut key = [0; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(100).unwrap(),
        &[0, 1, 2, 3, 4, 5, 6, 7],
        b"nice password",
        &mut key,
    );
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &key).unwrap();
    let nonce = Nonce::assume_unique_for_key(rand_vec);
    let nonce_sequence = OneNonceSequence::new(nonce);
    let mut s_key: aead::SealingKey<OneNonceSequence> = BoundKey::new(unbound_key, nonce_sequence);
    s_key
        .seal_in_place_append_tag(Aad::empty(), &mut in_out)
        .unwrap();
    println!("encrypted {:?}", &in_out);

    // decrypt
    let mut key = [0; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(100).unwrap(),
        &[0, 1, 2, 3, 4, 5, 6, 7],
        b"nice password",
        &mut key,
    );
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &key).unwrap();
    // Q: HOW CAN I NOT USE RAND_VEC, SINCE IN REAL PROGRAM IT WON'T BE ACCESSIBLE, RIGHT?
    let nonce = Nonce::assume_unique_for_key(rand_vec);
    let nonce_sequence = OneNonceSequence::new(nonce);
    let mut o_key: aead::OpeningKey<OneNonceSequence> = BoundKey::new(unbound_key, nonce_sequence);
    let decrypted = o_key
        .open_in_place(Aad::empty(), &mut in_out)
        .expect("can't decrypt");

    assert_eq!(decrypted, text.as_bytes());
}
