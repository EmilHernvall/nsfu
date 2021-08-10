use std::io::Write;

use ring::{
    hkdf,
    aead::{self, BoundKey},
};

use crate::{
    Result,
    Error,
    WritablePacketFragment,
    primitives::VarOpaque,
};

pub struct HkdfLabel {
   length: u16,
   label: VarOpaque<u8>,
   context: VarOpaque<u8>,
}

impl HkdfLabel {
    pub fn expand(label: &str, context: &[u8], length: u16) -> Result<Vec<u8>> {
        Self::new(label, context, length).to_bytes()
    }

    pub fn new(label: &str, context: &[u8], length: u16) -> Self {
        let label = format!("tls13 {}", label).as_bytes().into();
        let context = context.into();
        HkdfLabel {
            length,
            label,
            context,
        }
    }

    pub fn to_bytes(self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        self.write(&mut buffer)?;

        Ok(buffer)
    }
}

impl WritablePacketFragment for HkdfLabel {
    fn written_length(&self) -> usize {
        2 + self.label.written_length() + self.context.written_length()
    }

    fn write<B: Write>(&self, buffer: &mut B) -> Result<usize> {
        let mut written = 0;
        written += self.length.write(buffer)?;
        written += self.label.write(buffer)?;
        written += self.context.write(buffer)?;
        Ok(written)
    }
}


pub struct IvLen;

impl hkdf::KeyType for IvLen {
    fn len(&self) -> usize {
        aead::NONCE_LEN
    }
}

pub struct Iv([u8; aead::NONCE_LEN]);

impl From<hkdf::Okm<'_, IvLen>> for Iv {
    fn from(okm: hkdf::Okm<IvLen>) -> Self {
        let mut r = Self(Default::default());
        okm.fill(&mut r.0[..]).unwrap();
        r
    }
}

impl Iv {
    fn to_nonce_sequence(self) -> TlsNonceSequence {
        TlsNonceSequence {
            iv: self,
            seq: 0,
        }
    }
}

pub struct TlsNonceSequence {
    iv: Iv,
    seq: u64,
}

impl aead::NonceSequence for TlsNonceSequence {
    fn advance(&mut self) -> std::result::Result<aead::Nonce, ring::error::Unspecified> {
        let [ a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11 ] = self.iv.0;
        let [ b4, b5, b6, b7, b8, b9, b10, b11 ] = self.seq.to_be_bytes();

        self.seq += 1;

        Ok(aead::Nonce::assume_unique_for_key([
            a0, a1, a2, a3,
            a4 ^ b4, a5 ^ b5, a6 ^ b6, a7 ^ b7,
            a8 ^ b8, a9 ^ b9, a10 ^ b10, a11 ^ b11,
        ]))
    }
}

pub fn derive_secrets(shared_secret: &[u8], hello_hash: &[u8]) -> Result<(aead::OpeningKey<TlsNonceSequence>, aead::SealingKey<TlsNonceSequence>)> {
    let zero: Vec<u8> = (0..32).map(|_| 0).collect();

    let empty_hash: Vec<u8> = {
        use sha2::Digest;

        let mut hasher = sha2::Sha256::new();
        hasher.update(b"");
        hasher.finalize().to_vec()
    };

    let derived_secret: hkdf::Salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &zero)
        .extract(&zero)
        .expand(
            &[ &HkdfLabel::expand("derived", &empty_hash, 32)? ],
            hkdf::HKDF_SHA256,
        )
        .map_err(|_| Error::Hkdf)?
        .into();

    let handshake_secret = derived_secret
        .extract(&shared_secret);

    let client_handshake_traffic_secret: hkdf::Prk = handshake_secret
        .expand(
            &[ &HkdfLabel::expand("c hs traffic", &hello_hash, 32)? ],
            hkdf::HKDF_SHA256,
        )
        .map_err(|_| Error::Hkdf)?
        .into();

    let server_handshake_traffic_secret: hkdf::Prk = handshake_secret
        .expand(
            &[ &HkdfLabel::expand("s hs traffic", &hello_hash, 32)? ],
            hkdf::HKDF_SHA256,
        )
        .map_err(|_| Error::Hkdf)?
        .into();

    let client_handshake_key: aead::UnboundKey = client_handshake_traffic_secret
        .expand(
            &[ &HkdfLabel::expand("key", &[], 16)? ],
            &aead::AES_128_GCM,
        )
        .map_err(|_| Error::Hkdf)?
        .into();

    let server_handshake_key: aead::UnboundKey = server_handshake_traffic_secret
        .expand(
            &[ &HkdfLabel::expand("key", &[], 16)? ],
            &aead::AES_128_GCM,
        )
        .map_err(|_| Error::Hkdf)?
        .into();

    let client_handshake_iv: Iv = client_handshake_traffic_secret
        .expand(
            &[ &HkdfLabel::expand("iv", &[], 12)? ],
            IvLen,
        )
        .map_err(|_| Error::Hkdf)?
        .into();

    let server_handshake_iv: Iv = server_handshake_traffic_secret
        .expand(
            &[ &HkdfLabel::expand("iv", &[], 12)? ],
            IvLen,
        )
        .map_err(|_| Error::Hkdf)?
        .into();

    let client_handshake_key = aead::SealingKey::new(
        client_handshake_key,
        client_handshake_iv.to_nonce_sequence(),
    );

    let server_handshake_key = aead::OpeningKey::new(
        server_handshake_key,
        server_handshake_iv.to_nonce_sequence(),
    );

    Ok((server_handshake_key, client_handshake_key))
}
