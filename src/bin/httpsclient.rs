use std::io::Write;
use std::io::Cursor;
use std::net::ToSocketAddrs;

use ring::{agreement, rand::SecureRandom};
use sha2::Digest;

use nsfu::{ReadablePacketFragment, WritablePacketFragment};

#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum ClientState {
    Start,
    WaitServerHello,
    WaitEncryptedExtensions,
    WaitCertificate,
    WaitCertificateVerify,
    WaitFinished,
    Connected,
}

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
        // nsfu::Extension::ApplicationLayerProtocolNegotiation(
        //     vec![
        //         b"http/1.1".into(),
        //     ].into(),
        // ),
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

    println!("{:#?}", client_hello);

    let mut handshake_hasher = {
        let mut hasher = sha2::Sha256::new();
        client_hello.hash(&mut hasher)?;
        hasher
    };

    let client_hello = nsfu::RecordVariant::Handshake(
        client_hello,
    );

    let mut client_hello_buffer = Vec::new();
    client_hello.write(&mut client_hello_buffer)?;

    let mut socket = std::net::TcpStream::connect(addr)?;
    socket.write_all(&client_hello_buffer)?;

    let mut state = ClientState::WaitServerHello;
    let mut handshake_key_schedule = None;
    let mut application_key_schedule = None;
    loop {
        let mut context = nsfu::Context::default();

        let record = nsfu::Record::read(
            &mut socket,
            &mut context,
        )?;

        let aad: Vec<u8> = dbg!(record.preamble());

        match &record.variant {
            nsfu::RecordVariant::Handshake(message) if state == ClientState::WaitServerHello => {
                let selected_cipher_suite: nsfu::CipherSuite;
                let server_extensions: nsfu::TlsVec<nsfu::Extension, u16>;
                match message {
                    nsfu::Message::ServerHello { cipher_suite, extensions, .. } => {
                        selected_cipher_suite = cipher_suite.clone();
                        server_extensions = extensions.clone();
                    },
                    _ => panic!(),
                }

                println!("{:#?}", message);

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

                println!("Using cipher suite: {:?}", &selected_cipher_suite);
                println!("Using group: {:?}", &group);

                assert_eq!(nsfu::CipherSuite::TlsAes128GcmSha256, selected_cipher_suite);
                assert_eq!(nsfu::extension::NamedGroup::X25519, group.unwrap());

                let peer_public_key = peer_public_key.unwrap();

                handshake_key_schedule = Some(agreement::agree_ephemeral(
                    my_private_key.take().unwrap(),
                    &peer_public_key,
                    ring::error::Unspecified,
                    |key_material| {
                        match nsfu::key_schedule::HandshakeKeySchedule::derive(key_material, &handshake_hash) {
                            Ok(x) => Ok(x),
                            Err(e) => {
                                eprintln!("agree_ephemeral: {:?}", e);
                                Err(ring::error::Unspecified)
                            }
                        }
                    },
                ).unwrap());

                state = ClientState::WaitEncryptedExtensions;
            },
            nsfu::RecordVariant::ApplicationData(opaque) if state == ClientState::WaitEncryptedExtensions => {
                println!("Encrypted handshake record (length={})", opaque.len());
                let server_handshake_key = &mut handshake_key_schedule.as_mut().unwrap().server_handshake_key;
                let mut data = opaque.clone().into_inner();
                let data: &[u8] = server_handshake_key.open_in_place(
                    ring::aead::Aad::from(aad),
                    &mut data,
                ).unwrap();

                let mut buffer = Cursor::new(data);

                let mut server_verify_data = None;

                let mut server_finished_hash = None;
                let mut client_finished_hash = None;
                while data.len() - buffer.position() as usize > 1 {
                    let mut context = nsfu::Context::default();
                    let message = dbg!(nsfu::Message::read(&mut buffer, &mut context).unwrap());

                    match &message {
                        nsfu::handshake::Message::EncryptedExtensions { .. } => {
                            message.hash(&mut handshake_hasher)?;
                            state = ClientState::WaitCertificate;
                        },
                        nsfu::handshake::Message::Unknown { msg_type, .. } if *msg_type == nsfu::handshake::MessageType::Certificate => {
                            message.hash(&mut handshake_hasher)?;
                            state = ClientState::WaitCertificateVerify;
                        },
                        nsfu::handshake::Message::Unknown { msg_type, .. } if *msg_type == nsfu::handshake::MessageType::CertificateVerify => {
                            message.hash(&mut handshake_hasher)?;
                            state = ClientState::WaitFinished;
                        },
                        nsfu::handshake::Message::Finished { hash } => {
                            // The server hash doesn't include the finished message...
                            server_finished_hash = Some(handshake_hasher.clone().finalize());

                            // But the client finished message does include it.
                            message.hash(&mut handshake_hasher)?;
                            client_finished_hash = Some(handshake_hasher.clone().finalize());

                            server_verify_data = Some((**hash).clone());
                            state = ClientState::Connected;
                        },
                        _ => panic!()
                    }
                }

                println!("End of encrypted record");

                let server_finished_hash = server_finished_hash.unwrap().to_vec();
                let client_finished_hash = client_finished_hash.unwrap().to_vec();

                let server_finished_key = &handshake_key_schedule.as_ref().unwrap().server_finished_key;
                let client_finished_key = &handshake_key_schedule.as_ref().unwrap().client_finished_key;

                ring::hmac::verify(
                    server_finished_key, 
                    &server_finished_hash, 
                    &server_verify_data.unwrap(),
                ).expect("Finished hash failed to verify");

                // Prepare and send the finished message
                let client_verify_data = ring::hmac::sign(
                    client_finished_key, 
                    &client_finished_hash,
                ).as_ref().to_vec();

                let finished_message = dbg!(nsfu::handshake::Message::Finished {
                    hash: client_verify_data.clone().into(),
                });

                let mut finished_message_buffer = vec![];
                finished_message.write(&mut finished_message_buffer).unwrap();

                // Actual Tls 1.3 record type, 0x16 = Handshake
                finished_message_buffer.write(&[0x16]).unwrap();

                let finished_len = finished_message_buffer.len() + ring::aead::AES_128_GCM.tag_len();

                let finished_aad = ring::aead::Aad::from([
                    0x17, // ContentType::ApplicationData
                    0x3,  // ProtocolVersion (major)
                    0x3,  // ProtocolVersion (minor)
                    0,
                    finished_len as u8,
                ]);

                let client_handshake_key = &mut handshake_key_schedule.as_mut().unwrap().client_handshake_key;
                client_handshake_key.seal_in_place_append_tag(
                    finished_aad,
                    &mut finished_message_buffer,
                ).unwrap();

                assert_eq!(finished_len, finished_message_buffer.len());

                let finished_record = nsfu::RecordVariant::ApplicationData(finished_message_buffer.into());

                finished_record.write(&mut socket).unwrap();

                // Derive our application keys from the transcript hash
                let handshake_key_schedule = handshake_key_schedule.as_mut().unwrap();

                let mut local_application_key_schedule = 
                    handshake_key_schedule.derive_application_schedule(&client_finished_hash).unwrap();

                println!("Handshake complete!");

                {
                    // Prepare and send an actual HTTP request
                    let mut http_request = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", host).as_bytes().to_vec();

                    // Actual Tls 1.3 record type, 0x17 = Application Data
                    http_request.write(&[ 0x17 ]).unwrap();

                    let http_request_len = http_request.len() + ring::aead::AES_128_GCM.tag_len();

                    let http_request_aad = ring::aead::Aad::from([
                        0x17, // ContentType::ApplicationData
                        0x3,  // ProtocolVersion (major)
                        0x3,  // ProtocolVersion (minor)
                        0,
                        http_request_len as u8,
                    ]);

                    let client_application_key = &mut local_application_key_schedule.client_application_key;
                    client_application_key.seal_in_place_append_tag(http_request_aad, &mut http_request).unwrap();

                    assert_eq!(http_request_len, http_request.len());

                    let http_request_record = nsfu::RecordVariant::ApplicationData(http_request.into());
                    http_request_record.write(&mut socket).unwrap();
                }

                application_key_schedule = Some(local_application_key_schedule);
            }
            nsfu::RecordVariant::ApplicationData(opaque) if state == ClientState::Connected => {
                println!("Encrypted application record (length={})", opaque.len());
                let key_schedule = application_key_schedule.as_mut().unwrap();
                let server_application_key = &mut key_schedule.server_application_key;
                let mut data = opaque.clone().into_inner();
                let data: &[u8] = server_application_key.open_in_place(
                    ring::aead::Aad::from(aad),
                    &mut data,
                ).unwrap();

                let s = String::from_utf8_lossy(&*data);
                println!("{}", s);
            }
            _ => {
                println!("Unencrypted record: {:#?}", record);
            }
        }
    }
}
