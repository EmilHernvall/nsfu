use bytes::{Bytes, BytesMut, Buf};
use ring::{agreement, rand::SecureRandom};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    let client_hello = nsfu::Record::Handshake(
        nsfu::ProtocolVersion::tlsv1(),
        client_hello,
    );

    let mut client_hello_buffer = BytesMut::new();
    let written = client_hello.write(&mut client_hello_buffer)?;

    println!("{:#?}", client_hello);
    println!("written={}", written);
    println!("len={}", client_hello_buffer.len());

    // let mut client_hello_buffer: Bytes = client_hello_buffer.into();

    // let mut ctx = nsfu::Context::default();
    // let start = client_hello_buffer.remaining();
    // let client_hello_recovered = nsfu::Record::read(&mut client_hello_buffer, &mut ctx)?;
    // let end = client_hello_buffer.remaining();
    // assert_eq!(start - end, written);

    // println!("{:#?}", client_hello_recovered);

    // let mut socket = tokio::net::TcpStream::connect("127.0.0.1:8443").await?;
    let mut socket = tokio::net::TcpStream::connect("142.250.74.132:443").await?;
    // let mut socket = tokio::net::TcpStream::connect("205.251.219.56:443").await?;
    socket.write_all(&client_hello_buffer).await?;

    let mut server_response_buffer = BytesMut::new();
    loop {
        let read = socket.read_buf(&mut server_response_buffer).await?;
        println!("read {}", read);
        if read == 0 {
            break;
        }
    }

    let mut server_response_buffer: Bytes = server_response_buffer.into();

    let mut server_random: Option<nsfu::handshake::Random> = None;
    let mut selected_cipher_suite: Option<nsfu::CipherSuite> = None;
    let mut server_extensions: Option<nsfu::TlsVec<nsfu::Extension, 2>> = None;
    while server_response_buffer.remaining() > 0 {
        let mut context = nsfu::Context::default();
        let record = nsfu::Record::read(
            &mut server_response_buffer,
            &mut context,
        )?;

        println!("{:#?}", record);

        match record {
            nsfu::Record::Handshake(_, nsfu::Message::ServerHello {
                random,
                cipher_suite,
                extensions,
                ..
            }) => {
                server_random = Some(random);
                selected_cipher_suite = Some(cipher_suite);
                server_extensions = Some(extensions);
            },
            _ => {}
        }
    }

    let server_extensions = server_extensions.unwrap();

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

    dbg!(server_random);
    dbg!(selected_cipher_suite);
    dbg!(group);
    let peer_public_key = peer_public_key.unwrap();

    agreement::agree_ephemeral(
        my_private_key,
        &peer_public_key,
        ring::error::Unspecified,
        |_key_material| {
            dbg!(_key_material);
            Ok(())
        },
    ).unwrap();

    Ok(())
}
