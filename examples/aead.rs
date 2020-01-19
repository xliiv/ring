use ring::aead::{Aad, BoundKey, Nonce, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use ring::{aead, error};

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

fn generate_key<T: BoundKey<OneNonceSequence>>(rand_vec: [u8; 12]) -> T {
    // generate unbound_key
    let key = [0; 32];
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &key).unwrap();

    // generate nonce_sequence
    let nonce = Nonce::assume_unique_for_key(rand_vec);
    let nonce_sequence = OneNonceSequence::new(nonce);
    T::new(unbound_key, nonce_sequence)
}

fn main() {
    let text = "content to encrypt";
    let mut in_out = text.as_bytes().to_vec();
    println!("{:?}", &in_out);

    // generate nonce
    let rand_gen = SystemRandom::new();
    let mut rand_vec = [0u8; NONCE_LEN];
    rand_gen.fill(&mut rand_vec).unwrap();

    // encrypt
    let mut s_key: aead::SealingKey<OneNonceSequence> = generate_key(rand_vec);
    s_key
        .seal_in_place_append_tag(Aad::empty(), &mut in_out)
        .unwrap();
    println!("{:?}", &in_out);

    // decrypt
    let mut o_key: aead::OpeningKey<OneNonceSequence> = generate_key(rand_vec);
    o_key.open_in_place(Aad::empty(), &mut in_out).unwrap();
    println!("{:?}", &in_out);

    // how should i (in a real example) know the length of the original text?
    assert_eq!(in_out.as_slice(), text.as_bytes());
}
