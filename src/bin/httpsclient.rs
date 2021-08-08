use bytes::{Bytes, BytesMut, Buf};
use ring::{agreement, rand::SecureRandom};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use sha2::Digest;

use nsfu::{ReadablePacketFragment, WritablePacketFragment};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rng = ring::rand::SystemRandom::new();

    let my_private_key =
        agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();
    let my_public_key = my_private_key.compute_public_key().unwrap();

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
        nsfu::CipherSuite::TlsAes256GcmSha384,
    ].into();
    let supported_versions = vec![
        nsfu::ProtocolVersion::tlsv3(),
    ].into();
    let supported_groups = vec![
        nsfu::extension::NamedGroup::X25519,
    ].into();
    let signature_algorithms = vec![
        nsfu::extension::SignatureScheme::Ed25519,
    ].into();
    let extensions: nsfu::TlsVec<_, 2> = vec![
        nsfu::Extension::ServerName(
            vec![
                nsfu::extension::ServerName {
                    name_type: 0,
                    host_name: "www.google.com".as_bytes().into(),
                },
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

    let mut handshake_hasher = sha2::Sha256::new();
    client_hello.hash(&mut handshake_hasher)?;

    let client_hello = nsfu::Record::Handshake(
        nsfu::ProtocolVersion::tlsv1(),
        client_hello,
    );

    let mut client_hello_buffer = BytesMut::new();
    let written = client_hello.write(&mut client_hello_buffer)?;

    println!("{:#?}", client_hello);
    println!("written={}", written);
    println!("len={}", client_hello_buffer.len());

    let mut socket = tokio::net::TcpStream::connect("142.250.74.132:443").await?;
    socket.write_all(&client_hello_buffer).await?;

    let mut server_response_buffer = BytesMut::new();
    loop {
        let read = socket.read_buf(&mut server_response_buffer).await?;
        println!("read {} bytes from server", read);
        if read == 0 {
            break;
        }
    }

    let mut server_response_buffer: Bytes = server_response_buffer.into();

    let mut server_hello: Option<nsfu::handshake::Message> = None;
    let mut encrypted_records = vec![];
    while server_response_buffer.remaining() > 0 {
        let mut context = nsfu::Context::default();

        let aad: Vec<u8> = server_response_buffer[0..5].into();

        let record = nsfu::Record::read(
            &mut server_response_buffer,
            &mut context,
        )?;

        match record {
            nsfu::Record::Handshake(_, message) => {
                println!("Found server hello");
                server_hello = Some(message.clone());
            },
            nsfu::Record::ApplicationData(opaque) => {
                println!("Got one encrypted record");
                encrypted_records.push((aad, opaque));
            }
            _ => {
                println!("One other record: {:#?}", record);
            }
        }
    }

    let server_hello = server_hello.unwrap();
    server_hello.hash(&mut handshake_hasher)?;

    let handshake_hash = handshake_hasher.finalize();

    let selected_cipher_suite: nsfu::CipherSuite;
    let server_extensions: nsfu::TlsVec<nsfu::Extension, 2>;
    match server_hello {
        nsfu::Message::ServerHello { cipher_suite, extensions, .. } => {
            selected_cipher_suite = cipher_suite.clone();
            server_extensions = extensions.clone();
        },
        _ => panic!(),
    }

    let mut group: Option<nsfu::extension::NamedGroup> = None;
    let mut peer_public_key: Option<agreement::UnparsedPublicKey<_>> = None;
    for extension in server_extensions.0 {
        match extension {
            nsfu::Extension::KeyShare(nsfu::extension::KeyShare::ServerHello(entry)) => {
                group = Some(entry.group);
                peer_public_key = Some(agreement::UnparsedPublicKey::new(
                    &agreement::X25519,
                    entry.key_exchange.0,
                ));
            }
            _ => {}
        }
    }

    dbg!(&selected_cipher_suite);
    dbg!(&group);

    assert_eq!(nsfu::CipherSuite::TlsAes128GcmSha256, selected_cipher_suite);

    let peer_public_key = peer_public_key.unwrap();

    let (mut server_handshake_key, client_handshake_key) = agreement::agree_ephemeral(
        my_private_key,
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

    dbg!(&server_handshake_key);
    dbg!(&client_handshake_key);

    for (aad, nsfu::primitives::VarOpaque(mut data)) in encrypted_records {
        println!("Decrypting record");

        server_handshake_key.open_in_place(
            ring::aead::Aad::from(aad),
            &mut data,
        ).unwrap();

        let mut data: Bytes = data.into();

        while dbg!(data.remaining()) > 0 {
            let mut context = nsfu::Context::default();
            let message = nsfu::Message::read(&mut data, &mut context);
            dbg!(&message);
        }

        println!("Finished decrypting record");
    }

    Ok(())
}
