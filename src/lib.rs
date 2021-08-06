use thiserror::Error;
use bytes::BufMut;

mod bytes_ext;
pub mod primitives;
pub mod extension;
pub mod handshake;
pub mod alert;

use bytes_ext::*;
pub use primitives::{TlsVec, VarOpaque, FixedOpaque};
pub use extension::Extension;
pub use handshake::{Message, MessageType};

#[derive(Error, Debug)]
pub enum Error {
    #[error("end of file")]
    EOF,
    #[error("buffer overflow")]
    Overflow,
    #[error("unknown tls message type: {0}")]
    UnknownMsgType(u8),
    #[error("unknown tls cipher suite: {0}, {1}")]
    UnknownCipherSuite(u8, u8),
    #[error("illegal parameter: {0}")]
    IllegalParameter(&'static str),
    #[error("unknown named group: {0}")]
    UnknownNamedGroup(u16),
    #[error("unknown record type: {0}")]
    UnknownRecordType(u8),
    #[error("unimplemented message type: {0:?}")]
    UnimplementedMsgType(MessageType),
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct Context {
    pub message_type: Option<MessageType>,
}

impl Default for Context {
    fn default() -> Self {
        Context {
            message_type: None,
        }
    }
}

pub trait ReadablePacketFragment {
    fn read<B: BufExt>(buffer: &mut B, ctx: &mut Context) -> Result<Self>
    where Self: Sized;
}

pub trait WritablePacketFragment {
    fn written_length(&self) -> usize;
    fn write<B: BufMut>(&self, buffer: &mut B) -> Result<usize>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolVersion(pub u16);

impl ProtocolVersion {
    pub fn tlsv1() -> Self {
        ProtocolVersion(0x0301)
    }

    pub fn tlsv2() -> Self {
        ProtocolVersion(0x0303)
    }

    pub fn tlsv3() -> Self {
        ProtocolVersion(0x0304)
    }
}

impl ReadablePacketFragment for ProtocolVersion {
    fn read<B: BufExt>(buffer: &mut B, _ctx: &mut Context) -> Result<Self> {
        let protocol_version = buffer.read_u16()?;
        Ok(ProtocolVersion(protocol_version))
    }
}

impl WritablePacketFragment for ProtocolVersion {
    fn written_length(&self) -> usize {
        2
    }

    fn write<B: BufMut>(&self, buffer: &mut B) -> Result<usize> {
        buffer.put_u16(self.0);
        Ok(2)
    }
}

/// Cryptographic suite selector
#[derive(Clone, Debug)]
pub enum CipherSuite {
      TlsAes128Ccm8Sha256,
      TlsAes128CcmSha256,
      TlsAes128GcmSha256,
      TlsAes256GcmSha384,
      TlsChacha20poly1305Sha256,
      Unknown(u8, u8),
}

impl ReadablePacketFragment for CipherSuite {
    fn read<B: BufExt>(buffer: &mut B, _ctx: &mut Context) -> Result<Self> {
        let mut selector = [0; 2];
        buffer.read_slice(&mut selector)?;

        match selector {
            [0x13, 0x05] => Ok(CipherSuite::TlsAes128Ccm8Sha256),
            [0x13, 0x04] => Ok(CipherSuite::TlsAes128CcmSha256),
            [0x13, 0x01] => Ok(CipherSuite::TlsAes128GcmSha256),
            [0x13, 0x02] => Ok(CipherSuite::TlsAes256GcmSha384),
            [0x13, 0x03] => Ok(CipherSuite::TlsChacha20poly1305Sha256),
            [a, b] => Ok(CipherSuite::Unknown(a, b))
        }
    }
}

impl WritablePacketFragment for CipherSuite {
    fn written_length(&self) -> usize {
        2
    }

    fn write<B: BufMut>(&self, buffer: &mut B) -> Result<usize> {
        let selector = match self {
            CipherSuite::TlsAes128Ccm8Sha256 => [0x13, 0x05],
            CipherSuite::TlsAes128CcmSha256 => [0x13, 0x04],
            CipherSuite::TlsAes128GcmSha256 => [0x13, 0x01],
            CipherSuite::TlsAes256GcmSha384 => [0x13, 0x02],
            CipherSuite::TlsChacha20poly1305Sha256 => [0x13, 0x03],
            CipherSuite::Unknown(a, b) => return Err(Error::UnknownCipherSuite(*a, *b)),
        };
        buffer.put_slice(&selector);
        Ok(2)
    }
}

#[derive(Clone,Debug)]
pub enum Record {
    Invalid(VarOpaque<2>),
    ChangeCipherSpec(VarOpaque<2>),
    Alert(alert::AlertLevel, alert::AlertDescription),
    Handshake(ProtocolVersion, Message),
    ApplicationData(VarOpaque<2>),
}

impl ReadablePacketFragment for Record {
    fn read<B: BufExt>(buffer: &mut B, ctx: &mut Context) -> Result<Self> {
        let content_type = dbg!(buffer.read_u8()?);
        let version = ProtocolVersion::read(buffer, ctx)?;

        match content_type {
            0 => {
                let opaque = VarOpaque::read(buffer, ctx)?;
                Ok(Record::Invalid(opaque))
            },
            20 => {
                let opaque = VarOpaque::read(buffer, ctx)?;
                Ok(Record::ChangeCipherSpec(opaque))
            },
            21 => {
                let _length = buffer.read_u16()?;
                let level = alert::AlertLevel::read(buffer, ctx)?;
                let description = alert::AlertDescription::read(buffer, ctx)?;
                Ok(Record::Alert(level, description))
            },
            22 => {
                let length = buffer.read_u16()?;
                let start = buffer.remaining();
                let message = Message::read(buffer, ctx)?;
                let end = buffer.remaining();
                assert_eq!(start - end, length as usize);
                Ok(Record::Handshake(version, message))
            },
            23 => {
                let opaque = VarOpaque::read(buffer, ctx)?;
                Ok(Record::ApplicationData(opaque))
            },
            _ => {
                Err(Error::UnknownRecordType(content_type))
            },
        }
    }
}

impl WritablePacketFragment for Record {
    fn written_length(&self) -> usize {
        let written = match self {
            Record::Invalid(opaque) => opaque.written_length(),
            Record::ChangeCipherSpec(opaque) => opaque.written_length(),
            Record::Alert(_level, _description) => todo!(),
            Record::Handshake(_version, message) => 2 + message.written_length(),
            Record::ApplicationData(opaque) => opaque.written_length(),
        };

        written + 3
    }

    fn write<B: BufMut>(&self, buffer: &mut B) -> Result<usize> {
        let mut written = 0;

        match self {
            Record::Invalid(_opaque) => todo!(),
            Record::ChangeCipherSpec(_opaque) => todo!(),
            Record::Alert(level, description) => {
                buffer.put_u8(21);
                written += 1;
                written += ProtocolVersion::tlsv1().write(buffer)?;
                buffer.put_u16(2);
                written += 2;
                written += level.write(buffer)?;
                written += description.write(buffer)?;
            },
            Record::Handshake(version, message) => {
                buffer.put_u8(22);
                written += 1;
                written += version.write(buffer)?;
                buffer.put_u16(message.written_length() as u16);
                written += 2;
                written += message.write(buffer)?;
            },
            Record::ApplicationData(_opaque) => todo!(),
        }

        Ok(written)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use bytes::{Buf, Bytes, BytesMut};

    #[test]
    fn test_encode_decode_alert() {
        use alert::*;

        let alert = Record::Alert(
            AlertLevel::Fatal,
            AlertDescription::InternalError,
        );

        let mut buffer = BytesMut::new();
        let written = alert.write(&mut buffer).unwrap();
        assert_eq!(7, written);

        let mut buffer: Bytes = buffer.into();

        let mut context = Context::default();

        let start = buffer.remaining();
        let alert: Record = Record::read(&mut buffer, &mut context).unwrap();
        let end = buffer.remaining();
        assert_eq!(7, start - end);

        match alert {
            Record::Alert(AlertLevel::Fatal, AlertDescription::InternalError) => {},
            _ => panic!()
        }
    }
}
