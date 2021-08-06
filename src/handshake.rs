use bytes::BufMut;

use crate::{
    Result,
    Error,
    ReadablePacketFragment,
    WritablePacketFragment,
    Context,
    ProtocolVersion,
    CipherSuite,
    extension::Extension,
    bytes_ext::BufExt,
    primitives::{FixedOpaque, VarOpaque, TlsVec},
};

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
}

impl ReadablePacketFragment for MessageType {
    fn read<B: BufExt>(buffer: &mut B, _ctx: &mut Context) -> Result<Self> {
        let msg_type = buffer.read_u8()?;
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
            _ => Err(Error::UnknownMsgType(msg_type)),
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
        }
    }
}

#[derive(Clone,Debug)]
pub enum Message {
    ClientHello {
        version: ProtocolVersion,
        random: Random,
        legacy_session_id: VarOpaque<1>,
        cipher_suites: TlsVec<CipherSuite, 2>,
        extensions: TlsVec<Extension, 2>,
    },
    ServerHello {
        version: ProtocolVersion,
        random: Random,
        legacy_session_id: VarOpaque<1>,
        cipher_suite: CipherSuite,
        extensions: TlsVec<Extension, 2>,
    },
    EncryptedExtensions {
        extensions: TlsVec<Extension, 2>,
    },
}

impl Message {
    pub fn msg_type(&self) -> MessageType {
        match self {
            Message::ClientHello { .. } => MessageType::ClientHello,
            Message::ServerHello { .. } => MessageType::ServerHello,
            Message::EncryptedExtensions { .. } => MessageType::EncryptedExtensions,
        }
    }
}

impl ReadablePacketFragment for Message {
    fn read<B: BufExt>(buffer: &mut B, ctx: &mut Context) -> Result<Self> {
        let msg_type = dbg!(MessageType::read(buffer, ctx)?);

        ctx.message_type = Some(msg_type);

        match msg_type {
            MessageType::ClientHello => {
                let _msg_len = buffer.read_u24()?;

                let version = ProtocolVersion::read(buffer, ctx)?;
                let random = Random::read(buffer, ctx)?;

                let legacy_session_id = VarOpaque::read(buffer, ctx)?;

                let cipher_suites = TlsVec::read(buffer, ctx)?;

                let legacy_compression_methods_len = buffer.read_u8()?;
                if legacy_compression_methods_len != 1 {
                    return Err(Error::IllegalParameter("legacy_compression_methods_len"));
                }

                let legacy_compression_method = buffer.read_u8()?;
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
                let _msg_len = dbg!(buffer.read_u24()?);

                let version = ProtocolVersion::read(buffer, ctx)?;
                let random = Random::read(buffer, ctx)?;

                let legacy_session_id = VarOpaque::read(buffer, ctx)?;

                let cipher_suite = dbg!(CipherSuite::read(buffer, ctx)?);

                let legacy_compression_method = dbg!(buffer.read_u8()?);
                if legacy_compression_method != 0 {
                    return Err(Error::IllegalParameter("legacy_compression_method"));
                }

                let extensions = dbg!(TlsVec::read(buffer, ctx)?);

                Ok(Message::ServerHello {
                    version,
                    random,
                    legacy_session_id,
                    cipher_suite,
                    extensions,
                })
            }
            MessageType::EncryptedExtensions => {
                let _msg_len = buffer.read_u24()?;
                let extensions = TlsVec::read(buffer, ctx)?;
                Ok(Message::EncryptedExtensions { extensions })
            }
            _ => return Err(Error::UnimplementedMsgType(msg_type)),
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
        }

        written
    }

    fn write<B: BufMut>(&self, buffer: &mut B) -> Result<usize> {
        let mut written = 4;

        buffer.put_u8(self.msg_type().num());

        // 24-bit message length
        let [_, _, _, _, _, a, b, c] = (self.written_length() - 4).to_be_bytes();
        buffer.put_u8(a);
        buffer.put_u8(b);
        buffer.put_u8(c);

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
                buffer.put_u8(1);
                buffer.put_u8(0);
                written += 2;

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
                buffer.put_u8(0);

                written += extensions.write(buffer)?;
            }
            Message::EncryptedExtensions { extensions } => {
                written += extensions.write(buffer)?;
            }
        }

        Ok(written)
    }
}


