use std::io::{Read, Write};

use crate::{
    Result,
    Error,
    ReadablePacketFragment,
    WritablePacketFragment,
    Context,
    ProtocolVersion,
    MessageType,
    primitives::{VarOpaque, TlsVec},
};

#[derive(Clone, Debug)]
pub enum SupportedVersions {
    ClientHello(TlsVec<ProtocolVersion, u8>),
    ServerHello(ProtocolVersion),
}

#[derive(Clone, Debug)]
pub struct ServerName {
    pub name_type: u8,
    pub host_name: VarOpaque<u16>,
}

impl ReadablePacketFragment for ServerName {
    fn read<B: Read>(buffer: &mut B, ctx: &mut Context) -> Result<Self> {
        let name_type = u8::read(buffer, ctx)?;
        let host_name = VarOpaque::read(buffer, ctx)?;
        Ok(ServerName {
            name_type,
            host_name,
        })
    }
}

impl WritablePacketFragment for ServerName {
    fn written_length(&self) -> usize {
        1 + self.host_name.written_length()
    }

    fn write<B: Write>(&self, buffer: &mut B) -> Result<usize> {
        self.name_type.write(buffer)?;
        self.host_name.write(buffer)?;
        Ok(1 + self.host_name.written_length())
    }
}

#[derive(Clone, Debug)]
pub struct OIDFilter {
    pub certificate_extension_oid: VarOpaque<u8>,
    pub certificate_extension_values: VarOpaque<u16>,
}

impl ReadablePacketFragment for OIDFilter {
    fn read<B: Read>(buffer: &mut B, ctx: &mut Context) -> Result<Self> {
        let certificate_extension_oid = VarOpaque::read(buffer, ctx)?;
        let certificate_extension_values = VarOpaque::read(buffer, ctx)?;
        Ok(OIDFilter {
            certificate_extension_oid,
            certificate_extension_values,
        })
    }
}

impl WritablePacketFragment for OIDFilter {
    fn written_length(&self) -> usize {
        self.certificate_extension_oid.written_length()
            + self.certificate_extension_values.written_length()
    }

    fn write<B: Write>(&self, buffer: &mut B) -> Result<usize> {
        self.certificate_extension_oid.write(buffer)?;
        self.certificate_extension_values.write(buffer)?;
        Ok(self.written_length())
    }
}

#[derive(Clone, Debug)]
pub struct KeyShareEntry {
    pub group: NamedGroup,
    pub key_exchange: VarOpaque<u16>,
}

impl ReadablePacketFragment for KeyShareEntry {
    fn read<B: Read>(buffer: &mut B, ctx: &mut Context) -> Result<Self> {
        let group = NamedGroup::read(buffer, ctx)?;
        let key_exchange = VarOpaque::read(buffer, ctx)?;
        Ok(KeyShareEntry {
            group,
            key_exchange,
        })
    }
}

impl WritablePacketFragment for KeyShareEntry {
    fn written_length(&self) -> usize {
        self.group.written_length() + self.key_exchange.written_length()
    }

    fn write<B: Write>(&self, buffer: &mut B) -> Result<usize> {
        self.group.write(buffer)?;
        self.key_exchange.write(buffer)?;
        Ok(self.written_length())
    }
}

/// 2 bytes
#[derive(Clone, Copy, Debug)]
pub enum NamedGroup {
    // Elliptic Curve Groups (ECDHE)
    SECP256R1,
    SECP384R1,
    SECP521R1,
    X25519,
    X448,

    // Finite Field Groups (DHE)
    FFDHE2048,
    FFDHE3072,
    FFDHE4096,
    FFDHE6144,
    FFDHE8192,
}

impl ReadablePacketFragment for NamedGroup {
    fn read<B: Read>(buffer: &mut B, ctx: &mut Context) -> Result<Self> {
        let named_group = u16::read(buffer, ctx)?;
        match named_group {
            // Elliptic Curve Groups (ECDHE)
            0x0017 => Ok(NamedGroup::SECP256R1),
            0x0018 => Ok(NamedGroup::SECP384R1),
            0x0019 => Ok(NamedGroup::SECP521R1),
            0x001D => Ok(NamedGroup::X25519),
            0x001E => Ok(NamedGroup::X448),

            // Finite Field Groups (DHE)
            0x0100 => Ok(NamedGroup::FFDHE2048),
            0x0101 => Ok(NamedGroup::FFDHE3072),
            0x0102 => Ok(NamedGroup::FFDHE4096),
            0x0103 => Ok(NamedGroup::FFDHE6144),
            0x0104 => Ok(NamedGroup::FFDHE8192),

            _ => Err(Error::UnknownNamedGroup(named_group)),
        }
    }
}

impl WritablePacketFragment for NamedGroup {
    fn written_length(&self) -> usize {
        2
    }

    fn write<B: Write>(&self, buffer: &mut B) -> Result<usize> {
        let named_group: u16 = match self {
            // Elliptic Curve Groups (ECDHE)
            NamedGroup::SECP256R1 => 0x0017,
            NamedGroup::SECP384R1 => 0x0018,
            NamedGroup::SECP521R1 => 0x0019,
            NamedGroup::X25519 => 0x001D,
            NamedGroup::X448 => 0x001E,

            // Finite Field Groups (DHE)
            NamedGroup::FFDHE2048 => 0x0100,
            NamedGroup::FFDHE3072 => 0x0101,
            NamedGroup::FFDHE4096 => 0x0102,
            NamedGroup::FFDHE6144 => 0x0103,
            NamedGroup::FFDHE8192 => 0x0104,
        };

        named_group.write(buffer)?;

        Ok(2)
    }
}

/// 2 bytes
#[derive(Clone, Debug)]
pub enum SignatureScheme {
    // RSASSA-PKCS1-v1_5 algorithms
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,

    // ECDSA algorithms */
    EcdsaSecp256r1Sha256,
    EcdsaSecp384r1Sha384,
    EcdsaSecp521r1Sha512,

    // RSASSA-PSS algorithms with public key OID rsaEncryption
    RsaPssRsaeSha256,
    RsaPssRsaeSha384,
    RsaPssRsaeSha512,

    // EdDSA algorithms
    Ed25519,
    Ed448,

    // RSASSA-PSS algorithms with public key OID RSASSA-PSS
    RsaPssPssSha256,
    RsaPssPssSha384,
    RsaPssPssSha512,

    // Legacy algorithms
    RsaPkcs1Sha1,
    EcdsaSha1,

    Unknown(u16),
}

impl ReadablePacketFragment for SignatureScheme {
    fn read<B: Read>(buffer: &mut B, ctx: &mut Context) -> Result<Self> {
        let signature_scheme = u16::read(buffer, ctx)?;
        match signature_scheme {
            0x0401 => Ok(SignatureScheme::RsaPkcs1Sha256),
            0x0501 => Ok(SignatureScheme::RsaPkcs1Sha384),
            0x0601 => Ok(SignatureScheme::RsaPkcs1Sha512),
            0x0403 => Ok(SignatureScheme::EcdsaSecp256r1Sha256),
            0x0503 => Ok(SignatureScheme::EcdsaSecp384r1Sha384),
            0x0603 => Ok(SignatureScheme::EcdsaSecp521r1Sha512),
            0x0804 => Ok(SignatureScheme::RsaPssRsaeSha256),
            0x0805 => Ok(SignatureScheme::RsaPssRsaeSha384),
            0x0806 => Ok(SignatureScheme::RsaPssRsaeSha512),
            0x0807 => Ok(SignatureScheme::Ed25519),
            0x0808 => Ok(SignatureScheme::Ed448),
            0x0809 => Ok(SignatureScheme::RsaPssPssSha256),
            0x080a => Ok(SignatureScheme::RsaPssPssSha384),
            0x080b => Ok(SignatureScheme::RsaPssPssSha512),
            0x0201 => Ok(SignatureScheme::RsaPkcs1Sha1),
            0x0203 => Ok(SignatureScheme::EcdsaSha1),
            _ => Ok(SignatureScheme::Unknown(signature_scheme)),
        }
    }
}

impl WritablePacketFragment for SignatureScheme {
    fn written_length(&self) -> usize {
        2
    }

    fn write<B: Write>(&self, buffer: &mut B) -> Result<usize> {
        let signature_scheme = match self {
            SignatureScheme::RsaPkcs1Sha256 => 0x0401,
            SignatureScheme::RsaPkcs1Sha384 => 0x0501,
            SignatureScheme::RsaPkcs1Sha512 => 0x0601,
            SignatureScheme::EcdsaSecp256r1Sha256 => 0x0403,
            SignatureScheme::EcdsaSecp384r1Sha384 => 0x0503,
            SignatureScheme::EcdsaSecp521r1Sha512 => 0x0603,
            SignatureScheme::RsaPssRsaeSha256 => 0x0804,
            SignatureScheme::RsaPssRsaeSha384 => 0x0805,
            SignatureScheme::RsaPssRsaeSha512 => 0x0806,
            SignatureScheme::Ed25519 => 0x0807,
            SignatureScheme::Ed448 => 0x0808,
            SignatureScheme::RsaPssPssSha256 => 0x0809,
            SignatureScheme::RsaPssPssSha384 => 0x080a,
            SignatureScheme::RsaPssPssSha512 => 0x080b,
            SignatureScheme::RsaPkcs1Sha1 => 0x0201,
            SignatureScheme::EcdsaSha1 => 0x0203,
            SignatureScheme::Unknown(x) => *x,
        };

        signature_scheme.write(buffer)?;

        Ok(2)
    }
}

#[derive(Clone, Debug)]
pub struct DistinguishedName(VarOpaque<u16>);

impl ReadablePacketFragment for DistinguishedName {
    fn read<B: Read>(buffer: &mut B, ctx: &mut Context) -> Result<Self> {
        let name = VarOpaque::read(buffer, ctx)?;
        Ok(DistinguishedName(name))
    }
}

impl WritablePacketFragment for DistinguishedName {
    fn written_length(&self) -> usize {
        self.0.written_length()
    }

    fn write<B: Write>(&self, buffer: &mut B) -> Result<usize> {
        self.0.write(buffer)
    }
}

#[derive(Clone, Debug)]
pub enum KeyShare {
    ClientHello(TlsVec<KeyShareEntry, u16>),
    HelloRetryRequest(NamedGroup), // TODO: wat?
    ServerHello(KeyShareEntry),
}

#[derive(Clone, Debug)]
pub enum Extension {
    ServerName(TlsVec<ServerName, u16>),
    MaxFragmentLength,
    StatusRequest,
    SupportedGroups(TlsVec<NamedGroup, u16>),
    SignatureAlgorithms(TlsVec<SignatureScheme, u16>),
    UseSrtp,
    Heartbeat,
    ApplicationLayerProtocolNegotiation(TlsVec<VarOpaque<u8>, u16>),
    SignedCertificateTimestamp,
    ClientCertificateType,
    ServerCertificateType,
    Padding,
    PreSharedKey,
    EarlyData,
    SupportedVersions(SupportedVersions),
    Cookie(VarOpaque<u16>),
    PskKeyExchangeModes,
    CertificateAuthorities(TlsVec<DistinguishedName, u16>),
    OidFilters(TlsVec<OIDFilter, u16>),
    PostHandshakeAuth,
    SignatureAlgorithmsCert(TlsVec<SignatureScheme, u16>),
    KeyShare(KeyShare),
    Unknown(u16, VarOpaque<u16>),
}

impl Extension {
    pub fn extension_type(&self) -> u16 {
        match self {
            Extension::ServerName(_) => 0,
            Extension::MaxFragmentLength => 1,
            Extension::StatusRequest => 5,
            Extension::SupportedGroups(_) => 10,
            Extension::SignatureAlgorithms(_) => 13,
            Extension::UseSrtp => 14,
            Extension::Heartbeat => 15,
            Extension::ApplicationLayerProtocolNegotiation(_) => 16,
            Extension::SignedCertificateTimestamp => 18,
            Extension::ClientCertificateType => 19,
            Extension::ServerCertificateType => 20,
            Extension::Padding => 21,
            Extension::PreSharedKey => 41,
            Extension::EarlyData => 42,
            Extension::SupportedVersions(_) => 43,
            Extension::Cookie(_) => 44,
            Extension::PskKeyExchangeModes => 45,
            Extension::CertificateAuthorities(_) => 47,
            Extension::OidFilters(_) => 48,
            Extension::PostHandshakeAuth => 49,
            Extension::SignatureAlgorithmsCert(_) => 50,
            Extension::KeyShare(_) => 51,
            Extension::Unknown(ext_type, _) => *ext_type,
        }
    }
}

impl ReadablePacketFragment for Extension {
    fn read<B: Read>(buffer: &mut B, ctx: &mut Context) -> Result<Self> {
        let extension_type = u16::read(buffer, ctx)?;
        let length = u16::read(buffer, ctx)?;

        match extension_type {
            0 => {
                if length == 0 {
                    return Ok(Extension::ServerName(vec![].into()));
                }

                let server_name_list = TlsVec::read(buffer, ctx)?;
                Ok(Extension::ServerName(server_name_list))
            }
            10 => {
                let supported_groups = TlsVec::read(buffer, ctx)?;
                Ok(Extension::SupportedGroups(supported_groups))
            }
            13 => {
                let signature_algorithms = TlsVec::read(buffer, ctx)?;
                Ok(Extension::SignatureAlgorithms(signature_algorithms))
            }
            16 => {
                let protocols = TlsVec::read(buffer, ctx)?;
                Ok(Extension::ApplicationLayerProtocolNegotiation(protocols))
            }
            43 if ctx.message_type == Some(MessageType::ClientHello) => {
                let versions = TlsVec::read(buffer, ctx)?;
                Ok(Extension::SupportedVersions(
                    SupportedVersions::ClientHello(versions),
                ))
            }
            43 if ctx.message_type == Some(MessageType::ServerHello) => {
                let version = ProtocolVersion::read(buffer, ctx)?;
                Ok(Extension::SupportedVersions(
                    SupportedVersions::ServerHello(version),
                ))
            }
            44 => {
                let cookie = VarOpaque::read(buffer, ctx)?;
                Ok(Extension::Cookie(cookie))
            }
            47 => {
                let ca = TlsVec::read(buffer, ctx)?;
                Ok(Extension::CertificateAuthorities(ca))
            }
            48 => {
                let oidfilters = TlsVec::read(buffer, ctx)?;
                Ok(Extension::OidFilters(oidfilters))
            }
            50 => {
                let signature_algorithms = TlsVec::read(buffer, ctx)?;
                Ok(Extension::SignatureAlgorithmsCert(signature_algorithms))
            }
            51 if ctx.message_type == Some(MessageType::ClientHello) => {
                let entries = TlsVec::read(buffer, ctx)?;
                Ok(Extension::KeyShare(KeyShare::ClientHello(entries)))
            }
            51 if ctx.message_type == Some(MessageType::ServerHello) => {
                let entry = KeyShareEntry::read(buffer, ctx)?;
                Ok(Extension::KeyShare(KeyShare::ServerHello(entry)))
            }
            _ => {
                let mut opaque = vec![0; length as usize];
                let read = buffer.read(&mut opaque)?;
                assert_eq!(read, length as usize);
                Ok(Extension::Unknown(extension_type, opaque.into()))
            },
        }
    }
}

impl WritablePacketFragment for Extension {
    fn written_length(&self) -> usize {
        let len = match self {
            Extension::ServerName(server_name_list) => server_name_list.written_length(),
            Extension::MaxFragmentLength => unimplemented!(),
            Extension::StatusRequest => unimplemented!(),
            Extension::SupportedGroups(supported_groups) => supported_groups.written_length(),
            Extension::SignatureAlgorithms(signature_algorithms) => {
                signature_algorithms.written_length()
            }
            Extension::UseSrtp => unimplemented!(),
            Extension::Heartbeat => unimplemented!(),
            Extension::ApplicationLayerProtocolNegotiation(protocols) => {
                protocols.written_length()
            },
            Extension::SignedCertificateTimestamp => unimplemented!(),
            Extension::ClientCertificateType => unimplemented!(),
            Extension::ServerCertificateType => unimplemented!(),
            Extension::Padding => unimplemented!(),
            Extension::PreSharedKey => unimplemented!(),
            Extension::EarlyData => unimplemented!(),
            Extension::SupportedVersions(SupportedVersions::ClientHello(versions)) => {
                versions.written_length()
            }
            Extension::SupportedVersions(SupportedVersions::ServerHello(version)) => {
                version.written_length()
            }
            Extension::Cookie(cookie) => cookie.written_length(),
            Extension::PskKeyExchangeModes => unimplemented!(),
            Extension::CertificateAuthorities(ca) => ca.written_length(),
            Extension::OidFilters(oidfilters) => oidfilters.written_length(),
            Extension::PostHandshakeAuth => unimplemented!(),
            Extension::SignatureAlgorithmsCert(signature_algorithms) => {
                signature_algorithms.written_length()
            }
            Extension::KeyShare(KeyShare::ClientHello(entries)) => entries.written_length(),
            Extension::KeyShare(KeyShare::ServerHello(entry)) => entry.written_length(),
            Extension::KeyShare(KeyShare::HelloRetryRequest(group)) => group.written_length(),
            Extension::Unknown(_, opaque) => opaque.written_length(),
        };

        len + 4
    }

    fn write<B: Write>(&self, buffer: &mut B) -> Result<usize> {
        let mut written = 0;

        let extension_type = self.extension_type();
        written += extension_type.write(buffer)?;

        let len = (self.written_length() - 4) as u16;
        written += len.write(buffer)?;

        match self {
            Extension::ServerName(server_name_list) => {
                written += server_name_list.write(buffer)?;
            }
            Extension::MaxFragmentLength => unimplemented!(),
            Extension::StatusRequest => unimplemented!(),
            Extension::SupportedGroups(supported_groups) => {
                written += supported_groups.write(buffer)?;
            }
            Extension::SignatureAlgorithms(signature_algorithms) => {
                written += signature_algorithms.write(buffer)?;
            }
            Extension::UseSrtp => unimplemented!(),
            Extension::Heartbeat => unimplemented!(),
            Extension::ApplicationLayerProtocolNegotiation(protocols) => {
                written += protocols.write(buffer)?;
            },
            Extension::SignedCertificateTimestamp => unimplemented!(),
            Extension::ClientCertificateType => unimplemented!(),
            Extension::ServerCertificateType => unimplemented!(),
            Extension::Padding => unimplemented!(),
            Extension::PreSharedKey => unimplemented!(),
            Extension::EarlyData => unimplemented!(),
            Extension::SupportedVersions(SupportedVersions::ClientHello(versions)) => {
                written += versions.write(buffer)?;
            }
            Extension::SupportedVersions(SupportedVersions::ServerHello(version)) => {
                written += version.write(buffer)?;
            }
            Extension::Cookie(cookie) => {
                written += cookie.write(buffer)?;
            }
            Extension::PskKeyExchangeModes => unimplemented!(),
            Extension::CertificateAuthorities(ca) => {
                written += ca.write(buffer)?;
            }
            Extension::OidFilters(oidfilters) => {
                written += oidfilters.write(buffer)?;
            }
            Extension::PostHandshakeAuth => unimplemented!(),
            Extension::SignatureAlgorithmsCert(signature_algorithms) => {
                written += signature_algorithms.write(buffer)?;
            }
            Extension::KeyShare(KeyShare::ClientHello(entries)) => {
                written += entries.write(buffer)?;
            }
            Extension::KeyShare(KeyShare::ServerHello(group)) => {
                written += group.write(buffer)?;
            }
            Extension::KeyShare(KeyShare::HelloRetryRequest(entry)) => {
                written += entry.write(buffer)?;
            }
            Extension::Unknown(_, opaque) => {
                written += opaque.write(buffer)?;
            }
        }

        Ok(written)
    }
}


