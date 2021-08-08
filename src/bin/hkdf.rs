/// Implementation of the sample computations on https://tls13.ulfheim.net/
/// as a sanity check on hkdf usage

use ring::{hkdf, aead};

use nsfu::key_schedule::HkdfLabel;

pub struct IvLen;

impl hkdf::KeyType for IvLen {
    fn len(&self) -> usize {
        aead::NONCE_LEN
    }
}

fn main() {
    let shared_secret = [
        0xdf, 0x4a, 0x29, 0x1b, 0xaa, 0x1e, 0xb7, 0xcf,
        0xa6, 0x93, 0x4b, 0x29, 0xb4, 0x74, 0xba, 0xad,
        0x26, 0x97, 0xe2, 0x9f, 0x1f, 0x92, 0x0d, 0xcc,
        0x77, 0xc8, 0xa0, 0xa0, 0x88, 0x44, 0x76, 0x24,
    ];

    let hello_hash = [
        0xda, 0x75, 0xce, 0x11, 0x39, 0xac, 0x80, 0xda,
        0xe4, 0x04, 0x4d, 0xa9, 0x32, 0x35, 0x0c, 0xf6,
        0x5c, 0x97, 0xcc, 0xc9, 0xe3, 0x3f, 0x1e, 0x6f,
        0x7d, 0x2d, 0x4b, 0x18, 0xb7, 0x36, 0xff, 0xd5,
    ];

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
            &[ &HkdfLabel::expand("derived", &empty_hash, 32).unwrap() ],
            hkdf::HKDF_SHA256,
        )
        .unwrap()
        .into();

    let handshake_secret = derived_secret
        .extract(&shared_secret);

    let client_handshake_traffic_secret: hkdf::Prk = handshake_secret
        .expand(
            &[ &HkdfLabel::expand("c hs traffic", &hello_hash, 32).unwrap() ],
            hkdf::HKDF_SHA256,
        )
        .unwrap()
        .into();

    let server_handshake_traffic_secret: hkdf::Prk = handshake_secret
        .expand(
            &[ &HkdfLabel::expand("s hs traffic", &hello_hash, 32).unwrap() ],
            hkdf::HKDF_SHA256,
        )
        .unwrap()
        .into();

    let mut client_handshake_key = vec![0; 16];
    client_handshake_traffic_secret
        .expand(
            &[ &HkdfLabel::expand("key", &[], 16).unwrap() ],
            &aead::AES_128_GCM,
        )
        .unwrap()
        .fill(&mut client_handshake_key)
        .unwrap();
    dbg!(hex::encode(client_handshake_key));

    let mut server_handshake_key = vec![0; 16];
    server_handshake_traffic_secret
        .expand(
            &[ &HkdfLabel::expand("key", &[], 16).unwrap() ],
            &aead::AES_128_GCM,
        )
        .unwrap()
        .fill(&mut server_handshake_key)
        .unwrap();
    dbg!(hex::encode(server_handshake_key));

    let mut client_handshake_iv = vec![0; 12];
    client_handshake_traffic_secret
        .expand(
            &[ &HkdfLabel::expand("iv", &[], 12).unwrap() ],
            IvLen,
        )
        .unwrap()
        .fill(&mut client_handshake_iv)
        .unwrap();
    dbg!(hex::encode(client_handshake_iv));

    let mut server_handshake_iv = vec![0; 12];
    server_handshake_traffic_secret
        .expand(
            &[ &HkdfLabel::expand("iv", &[], 12).unwrap() ],
            IvLen,
        )
        .unwrap()
        .fill(&mut server_handshake_iv)
        .unwrap();
    dbg!(hex::encode(server_handshake_iv));
}
