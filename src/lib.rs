use thiserror::Error;
use std::io::{Read, Write};

pub mod primitives;
pub mod extension;
pub mod handshake;
pub mod alert;
pub mod key_schedule;

pub use primitives::{TlsVec, VarOpaque, FixedOpaque};
pub use extension::Extension;
pub use handshake::{Message, MessageType};

#[derive(Error, Debug)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("end of file")]
    EOF,
    #[error("buffer overflow")]
    Overflow,
    #[error("unknown tls cipher suite: {0}, {1}")]
    UnknownCipherSuite(u8, u8),
    #[error("illegal parameter: {0}")]
    IllegalParameter(&'static str),
    #[error("unknown named group: {0}")]
    UnknownNamedGroup(u16),
    #[error("unknown record type: {0}")]
    UnknownRecordType(u8),
    #[error("hkdf")]
    Hkdf,
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
    fn read<B: Read>(buffer: &mut B, ctx: &mut Context) -> Result<Self>
    where Self: Sized;
}

pub trait WritablePacketFragment {
    fn written_length(&self) -> usize;
    fn write<B: Write>(&self, buffer: &mut B) -> Result<usize>;

    fn hash<H: sha2::Digest>(&self, hasher: &mut H) -> Result<()> {
        let mut buffer = vec![];
        self.write(&mut buffer)?;
        hasher.update(&buffer);

        Ok(())
    }
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
    fn read<B: Read>(buffer: &mut B, ctx: &mut Context) -> Result<Self> {
        let protocol_version = u16::read(buffer, ctx)?;
        Ok(ProtocolVersion(protocol_version))
    }
}

impl WritablePacketFragment for ProtocolVersion {
    fn written_length(&self) -> usize {
        2
    }

    fn write<B: Write>(&self, buffer: &mut B) -> Result<usize> {
        self.0.write(buffer)
    }
}

/// Cryptographic suite selector
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CipherSuite {
      TlsAes128Ccm8Sha256,
      TlsAes128CcmSha256,
      TlsAes128GcmSha256,
      TlsAes256GcmSha384,
      TlsChacha20poly1305Sha256,
      Unknown(u8, u8),
}

impl ReadablePacketFragment for CipherSuite {
    fn read<B: Read>(buffer: &mut B, ctx: &mut Context) -> Result<Self> {
        let selector: FixedOpaque<2> = FixedOpaque::read(buffer, ctx)?;

        match selector.0 {
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

    fn write<B: Write>(&self, buffer: &mut B) -> Result<usize> {
        let selector = match self {
            CipherSuite::TlsAes128Ccm8Sha256 => [0x13, 0x05],
            CipherSuite::TlsAes128CcmSha256 => [0x13, 0x04],
            CipherSuite::TlsAes128GcmSha256 => [0x13, 0x01],
            CipherSuite::TlsAes256GcmSha384 => [0x13, 0x02],
            CipherSuite::TlsChacha20poly1305Sha256 => [0x13, 0x03],
            CipherSuite::Unknown(a, b) => return Err(Error::UnknownCipherSuite(*a, *b)),
        };
        buffer.write(&selector)?;
        Ok(2)
    }
}

#[derive(Clone,Copy,Debug)]
pub enum RecordType {
    Invalid,
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
}

impl ReadablePacketFragment for RecordType {
    fn read<B: Read>(buffer: &mut B, ctx: &mut Context) -> Result<Self> {
        let record_type = u8::read(buffer, ctx)?;

        match record_type {
            0 => Ok(RecordType::Invalid),
            20 => Ok(RecordType::ChangeCipherSpec),
            21 => Ok(RecordType::Alert),
            22 => Ok(RecordType::Handshake),
            23 => Ok(RecordType::ApplicationData),
            _ => Err(Error::UnknownRecordType(record_type))
        }
    }
}

impl WritablePacketFragment for RecordType {
    fn written_length(&self) -> usize {
        2
    }

    fn write<B: Write>(&self, buffer: &mut B) -> Result<usize> {
        let record_type: u8 = match self {
            RecordType::Invalid => 0,
            RecordType::ChangeCipherSpec => 20,
            RecordType::Alert => 21,
            RecordType::Handshake => 22,
            RecordType::ApplicationData => 23,
        };

        record_type.write(buffer)?;

        Ok(2)
    }
}

#[derive(Clone,Debug)]
pub struct Record {
    record_type: RecordType,
    version: ProtocolVersion,
    length: u16,
    pub variant: RecordVariant,
}

impl Record {
    pub fn preamble(&self) -> Vec<u8> {
        let mut preamble = Vec::new();
        self.record_type.write(&mut preamble).unwrap();
        self.version.write(&mut preamble).unwrap();
        self.length.write(&mut preamble).unwrap();
        preamble
    }
}

#[derive(Clone,Debug)]
pub enum RecordVariant {
    Invalid(VarOpaque<u16>),
    ChangeCipherSpec(VarOpaque<u16>),
    Alert(alert::AlertLevel, alert::AlertDescription),
    Handshake(Message),
    ApplicationData(VarOpaque<u16>),
}

impl RecordVariant {
    pub fn record_type(&self) -> RecordType {
        match self {
            RecordVariant::Invalid(_) => RecordType::Invalid,
            RecordVariant::ChangeCipherSpec(_) => RecordType::ChangeCipherSpec,
            RecordVariant::Alert(_, _) => RecordType::Alert,
            RecordVariant::Handshake(_) => RecordType::Handshake,
            RecordVariant::ApplicationData(_) => RecordType::ApplicationData,
        }
    }
}

impl ReadablePacketFragment for Record {
    fn read<B: Read>(buffer: &mut B, ctx: &mut Context) -> Result<Self> {
        let record_type = RecordType::read(buffer, ctx)?;
        let version = ProtocolVersion::read(buffer, ctx)?;

        match record_type {
            RecordType::Invalid => {
                let opaque = VarOpaque::read(buffer, ctx)?;
                Ok(Record {
                    record_type,
                    version,
                    length: opaque.len() as u16,
                    variant: RecordVariant::Invalid(opaque),
                })
            },
            RecordType::ChangeCipherSpec => {
                let opaque = VarOpaque::read(buffer, ctx)?;
                Ok(Record {
                    record_type,
                    version,
                    length: opaque.len() as u16,
                    variant: RecordVariant::ChangeCipherSpec(opaque),
                })
            },
            RecordType::Alert => {
                let length = u16::read(buffer, ctx)?;
                let level = alert::AlertLevel::read(buffer, ctx)?;
                let description = alert::AlertDescription::read(buffer, ctx)?;
                Ok(Record {
                    record_type,
                    version,
                    length,
                    variant: RecordVariant::Alert(level, description),
                })
            },
            RecordType::Handshake => {
                let length = u16::read(buffer, ctx)?;
                let message = Message::read(buffer, ctx)?;
                Ok(Record {
                    record_type,
                    version,
                    length,
                    variant: RecordVariant::Handshake(message),
                })
            },
            RecordType::ApplicationData => {
                let opaque = VarOpaque::read(buffer, ctx)?;
                Ok(Record {
                    record_type,
                    version,
                    length: opaque.len() as u16,
                    variant: RecordVariant::ApplicationData(opaque),
                })
            },
        }
    }
}

impl WritablePacketFragment for RecordVariant {
    fn written_length(&self) -> usize {
        let written = match self {
            RecordVariant::Invalid(opaque) => opaque.written_length(),
            RecordVariant::ChangeCipherSpec(opaque) => opaque.written_length(),
            RecordVariant::Alert(level, description) => 2 + level.written_length() + description.written_length(),
            RecordVariant::Handshake(message) => 2 + message.written_length(),
            RecordVariant::ApplicationData(opaque) => opaque.written_length(),
        };

        written + 3
    }

    fn write<B: Write>(&self, buffer: &mut B) -> Result<usize> {
        let mut written = 0;

        written += self.record_type().write(buffer)?;
        written += ProtocolVersion::tlsv1().write(buffer)?;

        let len = (self.written_length() - 5) as u16;
        written += len.write(buffer)?;

        match &self {
            RecordVariant::Invalid(opaque) => {
                buffer.write(&opaque)?;
                written += opaque.len();
            },
            RecordVariant::ChangeCipherSpec(opaque) => {
                buffer.write(&opaque)?;
                written += opaque.len();
            },
            RecordVariant::Alert(level, description) => {
                written += level.write(buffer)?;
                written += description.write(buffer)?;
            },
            RecordVariant::Handshake(message) => {
                written += message.write(buffer)?
            },
            RecordVariant::ApplicationData(opaque) => {
                buffer.write(&opaque)?;
                written += opaque.len();
            },
        }

        Ok(written)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use std::io::Cursor;

    #[test]
    fn test_encode_decode_alert() {
        use alert::*;

        let alert = RecordVariant::Alert(
            AlertLevel::Fatal,
            AlertDescription::InternalError,
        );

        let mut buffer = Vec::new();
        let written = alert.write(&mut buffer).unwrap();
        assert_eq!(7, written);

        let mut buffer = Cursor::new(buffer);

        let mut context = Context::default();

        // let start = buffer.remaining();
        let alert: Record = Record::read(&mut buffer, &mut context).unwrap();
        // let end = buffer.remaining();
        // assert_eq!(7, start - end);

        match &alert.variant {
            RecordVariant::Alert(AlertLevel::Fatal, AlertDescription::InternalError) => {},
            _ => panic!()
        }
    }
}
