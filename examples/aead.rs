use ring::aead::{Aad, BoundKey, Nonce, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use ring::{aead, error};

struct OneNonceSequence(Option<aead::Nonce>);

impl OneNonceSequence {
    /// Constructs the sequence allowing `advance()` to be called
    /// `allowed_invocations` times.
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
    let mut in_out = b"content to encrypt".to_vec();
    dbg!(&in_out);

    // generate nonce
    let rand_gen = SystemRandom::new();
    let mut rand_vec = [0u8; NONCE_LEN];
    rand_gen.fill(&mut rand_vec).unwrap();
    let nonce = Nonce::assume_unique_for_key(rand_vec);
    let nonce_sequence = OneNonceSequence::new(nonce);

    // generate unbound_key
    let key = [0; 32];
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &key).unwrap();

    let mut s_key: aead::SealingKey<OneNonceSequence> = BoundKey::new(unbound_key, nonce_sequence);
    s_key
        .seal_in_place_append_tag(Aad::empty(), &mut in_out)
        .unwrap();
    dbg!(&in_out);
}
