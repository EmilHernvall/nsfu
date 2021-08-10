use std::io::Write;
use std::io::Cursor;
use std::net::ToSocketAddrs;

use ring::{agreement, rand::SecureRandom};
use sha2::Digest;

use nsfu::{ReadablePacketFragment, WritablePacketFragment};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::args()
        .nth(1)
        .expect("Provide the server to connect to");
    dbg!(&host);

    let addr = host
        .to_socket_addrs()
        .expect("Failed to parse")
        .next()
        .expect("Resolution failed");
    dbg!(addr);

    let rng = ring::rand::SystemRandom::new();

    let (mut my_private_key, my_public_key) = {
        let my_private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();
        let my_public_key = my_private_key.compute_public_key().unwrap();

        (Some(my_private_key), my_public_key)
    };

    let version = nsfu::ProtocolVersion::tlsv2();
    let random = {
        let mut v = [0; 32];
        rng.fill(&mut v).unwrap();
        nsfu::FixedOpaque::new(v)
    };
    let legacy_session_id = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ].into();
    let cipher_suites = vec![
        nsfu::CipherSuite::TlsAes128GcmSha256,
    ].into();
    let supported_versions = vec![
        nsfu::ProtocolVersion::tlsv3(),
    ].into();
    let supported_groups = vec![
        nsfu::extension::NamedGroup::X25519,
    ].into();
    let signature_algorithms = vec![
        nsfu::extension::SignatureScheme::Ed25519,
        nsfu::extension::SignatureScheme::Ed448,
        nsfu::extension::SignatureScheme::RsaPssRsaeSha256,
        nsfu::extension::SignatureScheme::RsaPssRsaeSha384,
    ].into();
    let extensions: nsfu::TlsVec<_, u16> = vec![
        nsfu::Extension::ServerName(
            vec![
                nsfu::extension::ServerName {
                    name_type: 0,
                    host_name: host.as_bytes().into(),
                },
            ].into(),
        ),
        nsfu::Extension::ApplicationLayerProtocolNegotiation(
            vec![
                b"http/1.1".into(),
            ].into(),
        ),
        nsfu::Extension::SupportedVersions(nsfu::extension::SupportedVersions::ClientHello(
            supported_versions,
        )),
        nsfu::Extension::SupportedGroups(
            supported_groups,
        ),
        nsfu::Extension::SignatureAlgorithms(
            signature_algorithms,
        ),
        nsfu::Extension::KeyShare(nsfu::extension::KeyShare::ClientHello(
            vec![
                nsfu::extension::KeyShareEntry {
                    group: nsfu::extension::NamedGroup::X25519,
                    key_exchange: my_public_key.into(),
                }
            ].into(),
        )),
    ].into();
    let client_hello = nsfu::Message::ClientHello {
        version,
        random,
        legacy_session_id,
        cipher_suites,
        extensions,
    };

    let mut handshake_hasher = {
        let mut hasher = sha2::Sha256::new();
        client_hello.hash(&mut hasher)?;
        hasher
    };

    let client_hello = nsfu::RecordVariant::Handshake(
        client_hello,
    );

    let mut client_hello_buffer = Vec::new();
    let written = client_hello.write(&mut client_hello_buffer)?;

    println!("{:#?}", client_hello);
    println!("written={}", written);
    println!("len={}", client_hello_buffer.len());

    let mut socket = std::net::TcpStream::connect(addr)?;
    socket.write_all(&client_hello_buffer)?;

    let mut server_handshake_key = None;
    let mut _client_handshake_key = None;
    loop {
        let mut context = nsfu::Context::default();

        let record = nsfu::Record::read(
            &mut socket,
            &mut context,
        )?;

        let aad: Vec<u8> = record.preamble();

        match &record.variant {
            nsfu::RecordVariant::Handshake(message) => {
                let selected_cipher_suite: nsfu::CipherSuite;
                let server_extensions: nsfu::TlsVec<nsfu::Extension, u16>;
                match message {
                    nsfu::Message::ServerHello { cipher_suite, extensions, .. } => {
                        selected_cipher_suite = cipher_suite.clone();
                        server_extensions = extensions.clone();
                    },
                    _ => panic!(),
                }

                println!("Found server hello");
                message.hash(&mut handshake_hasher)?;
                let handshake_hash = handshake_hasher.clone().finalize();

                let mut group: Option<nsfu::extension::NamedGroup> = None;
                let mut peer_public_key: Option<agreement::UnparsedPublicKey<_>> = None;
                for extension in server_extensions.iter() {
                    match extension {
                        nsfu::Extension::KeyShare(nsfu::extension::KeyShare::ServerHello(entry)) => {
                            group = Some(entry.group);
                            peer_public_key = Some(agreement::UnparsedPublicKey::new(
                                &agreement::X25519,
                                (*entry.key_exchange).clone(),
                            ));
                        }
                        _ => {}
                    }
                }

                dbg!(&selected_cipher_suite);
                dbg!(&group);

                assert_eq!(nsfu::CipherSuite::TlsAes128GcmSha256, selected_cipher_suite);

                let peer_public_key = peer_public_key.unwrap();

                let keys = agreement::agree_ephemeral(
                    my_private_key.take().unwrap(),
                    &peer_public_key,
                    ring::error::Unspecified,
                    |key_material| {
                        match nsfu::key_schedule::derive_secrets(key_material, &handshake_hash) {
                            Ok(x) => Ok(x),
                            Err(e) => {
                                eprintln!("agree_ephemeral: {:?}", e);
                                Err(ring::error::Unspecified)
                            }
                        }
                    },
                ).unwrap();

                server_handshake_key = Some(keys.0);
                _client_handshake_key = Some(keys.1);

                dbg!(&server_handshake_key);
                dbg!(&_client_handshake_key);
            },
            nsfu::RecordVariant::ApplicationData(opaque) => {
                println!("Got one encrypted record of len={}", opaque.len());
                let server_handshake_key = server_handshake_key.as_mut().unwrap();
                let mut data = opaque.clone().into_inner();
                let data: &[u8] = server_handshake_key.open_in_place(
                    ring::aead::Aad::from(aad),
                    &mut data,
                ).unwrap();

                let mut buffer = Cursor::new(data);

                // dbg!(hex::encode(&data));

                while data.len() - buffer.position() as usize > 1 {
                    let mut context = nsfu::Context::default();
                    let message = nsfu::Message::read(&mut buffer, &mut context).unwrap();
                    dbg!(&message);
                }

            }
            _ => {
                println!("One other record: {:#?}", record);
            }
        }
    }
}
