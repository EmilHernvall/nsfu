use std::io::{Read, Write};

use crate::{CipherSuite, Context, Error, ProtocolVersion, ReadablePacketFragment, Result, WritablePacketFragment, extension::Extension, primitives::{FixedOpaque, ReadLength, TlsVec, VarOpaque, u24}};

pub type Random = FixedOpaque<32>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageType {
    ClientHello,
    ServerHello,
    NewSessionTicket,
    EndOfEarlyData,
    EncryptedExtensions,
    Certificate,
    CertificateRequest,
    CertificateVerify,
    Finished,
    Alert,
    KeyUpdate,
    MessageHash,
    Unknown(u8),
}

impl ReadablePacketFragment for MessageType {
    fn read<B: Read>(buffer: &mut B, ctx: &mut Context) -> Result<Self> {
        let msg_type = u8::read(buffer, ctx)?;
        match msg_type {
            1 => Ok(MessageType::ClientHello),
            2 => Ok(MessageType::ServerHello),
            4 => Ok(MessageType::NewSessionTicket),
            5 => Ok(MessageType::EndOfEarlyData),
            8 => Ok(MessageType::EncryptedExtensions),
            11 => Ok(MessageType::Certificate),
            13 => Ok(MessageType::CertificateRequest),
            15 => Ok(MessageType::CertificateVerify),
            20 => Ok(MessageType::Finished),
            21 => Ok(MessageType::Alert),
            24 => Ok(MessageType::KeyUpdate),
            254 => Ok(MessageType::MessageHash),
            _ => Ok(MessageType::Unknown(msg_type)),
        }
    }
}

impl MessageType {
    pub fn num(&self) -> u8 {
        match self {
            MessageType::ClientHello => 1,
            MessageType::ServerHello => 2,
            MessageType::NewSessionTicket => 4,
            MessageType::EndOfEarlyData => 5,
            MessageType::EncryptedExtensions => 8,
            MessageType::Certificate => 11,
            MessageType::CertificateRequest => 13,
            MessageType::CertificateVerify => 15,
            MessageType::Finished => 20,
            MessageType::Alert => 21,
            MessageType::KeyUpdate => 24,
            MessageType::MessageHash => 254,
            MessageType::Unknown(x) => *x,
        }
    }
}

#[derive(Clone,Debug)]
pub enum Message {
    ClientHello {
        version: ProtocolVersion,
        random: Random,
        legacy_session_id: VarOpaque<u8>,
        cipher_suites: TlsVec<CipherSuite, u16>,
        extensions: TlsVec<Extension, u16>,
    },
    ServerHello {
        version: ProtocolVersion,
        random: Random,
        legacy_session_id: VarOpaque<u8>,
        cipher_suite: CipherSuite,
        extensions: TlsVec<Extension, u16>,
    },
    EncryptedExtensions {
        extensions: TlsVec<Extension, u16>,
    },
    Finished {
        hash: VarOpaque<u24>,
    },
    Unknown {
        msg_type: MessageType,
        data: VarOpaque<u24>,
    }
}

impl Message {
    pub fn msg_type(&self) -> MessageType {
        match self {
            Message::ClientHello { .. } => MessageType::ClientHello,
            Message::ServerHello { .. } => MessageType::ServerHello,
            Message::EncryptedExtensions { .. } => MessageType::EncryptedExtensions,
            Message::Finished { .. } => MessageType::Finished,
            Message::Unknown { msg_type, .. } => *msg_type,
        }
    }
}

impl ReadablePacketFragment for Message {
    fn read<B: Read>(buffer: &mut B, ctx: &mut Context) -> Result<Self> {
        let msg_type = MessageType::read(buffer, ctx)?;

        ctx.message_type = Some(msg_type);

        match msg_type {
            MessageType::ClientHello => {
                let _msg_len = u24::read(buffer, ctx)?;

                let version = ProtocolVersion::read(buffer, ctx)?;
                let random = Random::read(buffer, ctx)?;

                let legacy_session_id = VarOpaque::read(buffer, ctx)?;

                let cipher_suites = TlsVec::read(buffer, ctx)?;

                let legacy_compression_methods_len = u8::read(buffer, ctx)?;
                if legacy_compression_methods_len != 1 {
                    return Err(Error::IllegalParameter("legacy_compression_methods_len"));
                }

                let legacy_compression_method = u8::read(buffer, ctx)?;
                if legacy_compression_method != 0 {
                    return Err(Error::IllegalParameter("legacy_compression_method"));
                }

                let extensions = TlsVec::read(buffer, ctx)?;

                Ok(Message::ClientHello {
                    version,
                    random,
                    legacy_session_id,
                    cipher_suites,
                    extensions,
                })
            }
            MessageType::ServerHello => {
                let _msg_len = u24::read(buffer, ctx)?;

                let version = ProtocolVersion::read(buffer, ctx)?;
                let random = Random::read(buffer, ctx)?;

                let legacy_session_id = VarOpaque::read(buffer, ctx)?;

                let cipher_suite = CipherSuite::read(buffer, ctx)?;

                let legacy_compression_method = u8::read(buffer, ctx)?;
                if legacy_compression_method != 0 {
                    return Err(Error::IllegalParameter("legacy_compression_method"));
                }

                let extensions = TlsVec::read(buffer, ctx)?;

                Ok(Message::ServerHello {
                    version,
                    random,
                    legacy_session_id,
                    cipher_suite,
                    extensions,
                })
            }
            MessageType::EncryptedExtensions => {
                let _msg_len = u24::read(buffer, ctx)?;
                let extensions = TlsVec::read(buffer, ctx)?;
                Ok(Message::EncryptedExtensions { extensions })
            }
            MessageType::Finished => {
                let hash = VarOpaque::read(buffer, ctx)?;
                Ok(Message::Finished {
                    hash,
                })
            }
            _ => {
                let data = VarOpaque::read(buffer, ctx)?;
                Ok(Message::Unknown {
                    msg_type,
                    data,
                })
            },
        }
    }
}

impl WritablePacketFragment for Message {
    fn written_length(&self) -> usize {
        let mut written = 4;
        match self {
            Message::ClientHello {
                version,
                random,
                legacy_session_id,
                cipher_suites,
                extensions,
            } => {
                written += version.written_length();
                written += random.written_length();
                written += legacy_session_id.written_length();
                written += cipher_suites.written_length();

                // legacy_compression_methods
                written += 2;

                written += extensions.written_length();
            }
            Message::ServerHello {
                version,
                random,
                legacy_session_id,
                cipher_suite,
                extensions,
            } => {
                written += version.written_length();
                written += random.written_length();
                written += legacy_session_id.written_length();
                written += cipher_suite.written_length();

                // legacy_compression_method
                written += 1;

                written += extensions.written_length();
            }
            Message::EncryptedExtensions { extensions } => {
                written += extensions.written_length();
            }
            Message::Finished { hash } => {
                written += hash.len();
            }
            Message::Unknown { data, .. } => {
                written += data.written_length() - 3;
            }
        }

        written
    }

    fn write<B: Write>(&self, buffer: &mut B) -> Result<usize> {
        let mut written = 0;

        written += self.msg_type().num().write(buffer)?;

        // 24-bit message length
        written += u24(self.written_length() as u32 - 4).write(buffer)?;

        match self {
            Message::ClientHello {
                version,
                random,
                legacy_session_id,
                cipher_suites,
                extensions,
            } => {
                written += version.write(buffer)?;
                written += random.write(buffer)?;
                written += legacy_session_id.write(buffer)?;
                written += cipher_suites.write(buffer)?;

                // legacy_compression_methods
                written += 1u8.write(buffer)?;
                written += 0u8.write(buffer)?;

                written += extensions.write(buffer)?;
            }
            Message::ServerHello {
                version,
                random,
                legacy_session_id,
                cipher_suite,
                extensions,
            } => {
                written += version.write(buffer)?;
                written += random.write(buffer)?;
                written += legacy_session_id.write(buffer)?;
                written += cipher_suite.write(buffer)?;

                // legacy_compression_method
                written += 0u8.write(buffer)?;

                written += extensions.write(buffer)?;
            }
            Message::EncryptedExtensions { extensions } => {
                written += extensions.write(buffer)?;
            }
            Message::Finished { hash } => {
                written += hash.len() as usize;
                buffer.write(&*hash)?;
            }
            Message::Unknown { data, .. } => {
                written += data.len() as usize;
                buffer.write(&*data)?;
            }
        }

        Ok(written)
    }
}


