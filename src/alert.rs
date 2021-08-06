use crate::{
    Result,
    Error,
    ReadablePacketFragment,
    WritablePacketFragment,
    Context,
    bytes_ext::BufExt,
};

use bytes::BufMut;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AlertLevel {
    NotSet,
    Warning,
    Fatal,
}

impl ReadablePacketFragment for AlertLevel {
    fn read<B: BufExt>(buffer: &mut B, _ctx: &mut Context) -> Result<Self> {
        let level = buffer.read_u8()?;
        match level {
            0 => Ok(AlertLevel::NotSet),
            1 => Ok(AlertLevel::Warning),
            2 => Ok(AlertLevel::Fatal),
            _ => Err(Error::IllegalParameter("alert_level")),
        }
    }
}

impl WritablePacketFragment for AlertLevel {
    fn written_length(&self) -> usize {
        1
    }

    fn write<B: BufMut>(&self, buffer: &mut B) -> Result<usize> {
        let level = match self {
            AlertLevel::NotSet => 0,
            AlertLevel::Warning => 1,
            AlertLevel::Fatal => 2,
        };

        buffer.put_u8(level);

        Ok(1)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AlertDescription {
    CloseNotify,
    UnexpectedMessage,
    BadRecordMac,
    RecordOverflow,
    HandshakeFailure,
    BadCertificate,
    UnsupportedCertificate,
    CertificateRevoked,
    CertificateExpired,
    CertificateUnknown,
    IllegalParameter,
    UnknownCa,
    AccessDenied,
    DecodeError,
    DecryptError,
    ProtocolVersion,
    InsufficientSecurity,
    InternalError,
    InappropriateFallback,
    UserCanceled,
    MissingExtension,
    UnsupportedExtension,
    UnrecognizedName,
    BadCertificateStatusResponse,
    UnknownPskIdentity,
    CertificateRequired,
    NoApplicationProtocol,
}

impl ReadablePacketFragment for AlertDescription {
    fn read<B: BufExt>(buffer: &mut B, _ctx: &mut Context) -> Result<Self> {
        let description = buffer.read_u8()?;
        let description = match description {
            0 => AlertDescription::CloseNotify,
            10 => AlertDescription::UnexpectedMessage,
            20 => AlertDescription::BadRecordMac,
            22 => AlertDescription::RecordOverflow,
            40 => AlertDescription::HandshakeFailure,
            42 => AlertDescription::BadCertificate,
            43 => AlertDescription::UnsupportedCertificate,
            44 => AlertDescription::CertificateRevoked,
            45 => AlertDescription::CertificateExpired,
            46 => AlertDescription::CertificateUnknown,
            47 => AlertDescription::IllegalParameter,
            48 => AlertDescription::UnknownCa,
            49 => AlertDescription::AccessDenied,
            50 => AlertDescription::DecodeError,
            51 => AlertDescription::DecryptError,
            70 => AlertDescription::ProtocolVersion,
            71 => AlertDescription::InsufficientSecurity,
            80 => AlertDescription::InternalError,
            86 => AlertDescription::InappropriateFallback,
            90 => AlertDescription::UserCanceled,
            109 => AlertDescription::MissingExtension,
            110 => AlertDescription::UnsupportedExtension,
            112 => AlertDescription::UnrecognizedName,
            113 => AlertDescription::BadCertificateStatusResponse,
            115 => AlertDescription::UnknownPskIdentity,
            116 => AlertDescription::CertificateRequired,
            120 => AlertDescription::NoApplicationProtocol,
            _ => return Err(Error::IllegalParameter("alert_description")),
        };
        Ok(description)
    }
}

impl WritablePacketFragment for AlertDescription {
    fn written_length(&self) -> usize {
        1
    }

    fn write<B: BufMut>(&self, buffer: &mut B) -> Result<usize> {
        let description = match self {
            AlertDescription::CloseNotify => 0,
            AlertDescription::UnexpectedMessage => 10,
            AlertDescription::BadRecordMac => 20,
            AlertDescription::RecordOverflow => 22,
            AlertDescription::HandshakeFailure => 40,
            AlertDescription::BadCertificate => 42,
            AlertDescription::UnsupportedCertificate => 43,
            AlertDescription::CertificateRevoked => 44,
            AlertDescription::CertificateExpired => 45,
            AlertDescription::CertificateUnknown => 46,
            AlertDescription::IllegalParameter => 47,
            AlertDescription::UnknownCa => 48,
            AlertDescription::AccessDenied => 49,
            AlertDescription::DecodeError => 50,
            AlertDescription::DecryptError => 51,
            AlertDescription::ProtocolVersion => 70,
            AlertDescription::InsufficientSecurity => 71,
            AlertDescription::InternalError => 80,
            AlertDescription::InappropriateFallback => 86,
            AlertDescription::UserCanceled => 90,
            AlertDescription::MissingExtension => 109,
            AlertDescription::UnsupportedExtension => 110,
            AlertDescription::UnrecognizedName => 112,
            AlertDescription::BadCertificateStatusResponse => 113,
            AlertDescription::UnknownPskIdentity => 115,
            AlertDescription::CertificateRequired => 116,
            AlertDescription::NoApplicationProtocol => 120,
        };

        buffer.put_u8(description);

        Ok(1)
    }
}
