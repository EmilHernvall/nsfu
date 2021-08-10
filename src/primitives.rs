use std::{io::{Read, Write}, ops::Deref};

use crate::{
    Result,
    ReadablePacketFragment,
    WritablePacketFragment,
    Context,
};

struct AuditedReader<'a, R: Read> {
    inner: &'a mut R,
    read: usize,
}

impl<'a, R: Read> AuditedReader<'a, R> {
    fn new(inner: &'a mut R) -> Self {
        AuditedReader {
            inner,
            read: 0,
        }
    }
}

impl<R: Read> Read for AuditedReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.read += read;
        Ok(read)
    }
}

pub trait ReadLength {
    fn size_in_bytes() -> usize;
    fn from_usize(len: usize) -> Self;
    fn read_length<B: Read>(buffer: &mut B) -> Result<usize>;
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug)]
pub struct u24(pub u32);

impl ReadablePacketFragment for u8 {
    fn read<B: Read>(buffer: &mut B, _ctx: &mut Context) -> Result<Self> {
        let mut byte = [0u8; 1];
        buffer.read_exact(&mut byte)?;
        Ok(byte[0])
    }
}

impl ReadLength for u8 {
    fn size_in_bytes() -> usize {
        1
    }

    fn from_usize(len: usize) -> Self {
        len as u8
    }

    fn read_length<B: Read>(buffer: &mut B) -> Result<usize> {
        let mut byte = [0u8; 1];
        buffer.read_exact(&mut byte)?;
        Ok(byte[0] as usize)
    }
}

impl WritablePacketFragment for u8 {
    fn written_length(&self) -> usize {
        1
    }

    fn write<B: Write>(&self, buffer: &mut B) -> Result<usize> {
        buffer.write(&[ *self ])?;
        Ok(1)
    }
}

impl ReadablePacketFragment for u16 {
    fn read<B: Read>(buffer: &mut B, _ctx: &mut Context) -> Result<Self> {
        let mut bytes = [0u8; 2];
        buffer.read_exact(&mut bytes)?;
        Ok(u16::from_be_bytes(bytes))
    }
}

impl ReadLength for u16 {
    fn size_in_bytes() -> usize {
        2
    }

    fn from_usize(len: usize) -> Self {
        len as u16
    }

    fn read_length<B: Read>(buffer: &mut B) -> Result<usize> {
        let mut bytes = [0u8; 2];
        buffer.read_exact(&mut bytes)?;
        Ok(u16::from_be_bytes(bytes) as usize)
    }
}

impl WritablePacketFragment for u16 {
    fn written_length(&self) -> usize {
        2
    }

    fn write<B: Write>(&self, buffer: &mut B) -> Result<usize> {
        buffer.write(&u16::to_be_bytes(*self))?;
        Ok(2)
    }
}

impl ReadablePacketFragment for u24 {
    fn read<B: Read>(buffer: &mut B, _ctx: &mut Context) -> Result<Self> {
        let mut bytes = [0u8; 4];
        buffer.read_exact(&mut bytes[1..])?;
        Ok(u24(u32::from_be_bytes(bytes)))
    }
}

impl ReadLength for u24 {
    fn size_in_bytes() -> usize {
        3
    }

    fn from_usize(len: usize) -> Self {
        u24(len as u32)
    }

    fn read_length<B: Read>(buffer: &mut B) -> Result<usize> {
        let mut bytes = [0u8; 4];
        buffer.read_exact(&mut bytes[1..])?;
        Ok(u32::from_be_bytes(bytes) as usize)
    }
}

impl WritablePacketFragment for u24 {
    fn written_length(&self) -> usize {
        3
    }

    fn write<B: Write>(&self, buffer: &mut B) -> Result<usize> {
        let bytes = self.0.to_be_bytes();
        buffer.write(&bytes[1..])?;
        Ok(3)
    }
}

#[derive(Clone)]
pub struct TlsVec<T, N> {
    inner: Vec<T>,
    _len_type: std::marker::PhantomData<N>,
}

impl<T, N> TlsVec<T, N> {
    fn new(v: Vec<T>) -> Self {
        TlsVec {
            inner: v,
            _len_type: std::marker::PhantomData,
        }
    }
}

impl<T, N> Deref for TlsVec<T, N> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: std::fmt::Debug, N: ReadLength> std::fmt::Debug for TlsVec<T, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "TlsVec{} [{}]",
            N::size_in_bytes(),
            self.inner.iter().map(|x| format!("{:?}", x)).collect::<Vec<String>>().join(", "),
        ))
    }
}

impl<T: WritablePacketFragment, N> TlsVec<T, N> {
    pub fn payload_length(&self) -> usize {
        self.inner.iter().map(|x| x.written_length()).sum::<usize>()
    }
}

impl<T, N> From<Vec<T>> for TlsVec<T, N> {
    fn from(v: Vec<T>) -> Self {
        TlsVec::new(v)
    }
}

impl<T: ReadablePacketFragment, N: ReadLength> ReadablePacketFragment for TlsVec<T, N> {
    fn read<B: Read>(buffer: &mut B, ctx: &mut Context) -> Result<Self> {
        let len = N::read_length(buffer)? as usize;

        let mut buffer = AuditedReader::new(buffer);
        let mut vec = Vec::new();
        while buffer.read < len {
            vec.push(T::read(&mut buffer, ctx)?);
        }

        Ok(TlsVec::new(vec))
    }
}

impl<T: WritablePacketFragment, N: WritablePacketFragment + ReadLength> WritablePacketFragment for TlsVec<T, N> {
    fn written_length(&self) -> usize {
        N::size_in_bytes() + self.payload_length()
    }

    fn write<B: Write>(&self, buffer: &mut B) -> Result<usize> {
        let mut written = 0;
        let len = N::from_usize(self.payload_length());
        written += len.write(buffer)?;

        for element in &self.inner {
            written += element.write(buffer)?;
        }

        Ok(written)
    }
}

#[derive(Clone)]
pub struct FixedOpaque<const N: usize>(pub [u8; N]);

impl<const N: usize> FixedOpaque<N> {
    pub fn new(v: [u8; N]) -> Self {
        FixedOpaque(v)
    }
}

impl<const N: usize> std::fmt::Debug for FixedOpaque<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("FixedOpaque{}", N))
    }
}

impl<const N: usize> ReadablePacketFragment for FixedOpaque<N> {
    fn read<B: Read>(buffer: &mut B, _ctx: &mut Context) -> Result<Self> {
        let mut vec = [0; N];
        buffer.read_exact(&mut vec)?;
        Ok(FixedOpaque(vec))
    }
}

impl<const N: usize> WritablePacketFragment for FixedOpaque<N> {
    fn written_length(&self) -> usize {
        self.0.len()
    }

    fn write<B: Write>(&self, buffer: &mut B) -> Result<usize> {
        buffer.write(&self.0)?;
        Ok(N)
    }
}

#[derive(Clone)]
pub struct VarOpaque<N> {
    inner: Vec<u8>,
    _len_type: std::marker::PhantomData<N>,
}

impl<N> VarOpaque<N> {
    pub fn into_inner(self) -> Vec<u8> {
        let VarOpaque { inner, .. } = self;
        inner
    }
}

impl<N: ReadLength> std::fmt::Debug for VarOpaque<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("VarOpaque{}(len={})", N::size_in_bytes(), self.inner.len()))
    }
}

impl<N> Deref for VarOpaque<N> {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T, N> From<T> for VarOpaque<N> where T: AsRef<[u8]> {
    fn from(v: T) -> Self {
        VarOpaque {
            inner: v.as_ref().iter().cloned().collect(),
            _len_type: std::marker::PhantomData,
        }
    }
}

impl<N: ReadLength> ReadablePacketFragment for VarOpaque<N> {
    fn read<B: Read>(buffer: &mut B, _ctx: &mut Context) -> Result<Self> {
        let len = N::read_length(buffer)?;
        let mut vec = vec![0; len];
        buffer.read_exact(&mut vec)?;
        Ok(VarOpaque {
            inner: vec,
            _len_type: std::marker::PhantomData,
        })
    }
}

impl<N: ReadLength + WritablePacketFragment> WritablePacketFragment for VarOpaque<N> {
    fn written_length(&self) -> usize {
        N::size_in_bytes() + self.inner.len()
    }

    fn write<B: Write>(&self, buffer: &mut B) -> Result<usize> {
        let len = N::from_usize(self.inner.len());
        len.write(buffer)?;
        buffer.write(&self.inner)?;
        Ok(N::size_in_bytes() + self.inner.len())
    }
}

#[cfg(test)]
pub mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn test_encode_decode_tls_vec_u8() {
        use crate::ProtocolVersion;

        let mut buffer = Vec::new();

        let vec: TlsVec<ProtocolVersion, u8> = vec![
            ProtocolVersion::tlsv1(),
            ProtocolVersion::tlsv2(),
            ProtocolVersion::tlsv3(),
        ].into();

        let written = vec.write(&mut buffer).unwrap();
        assert_eq!(7, written);

        let mut buffer = Cursor::new(buffer);

        let mut context = Context::default();
        let decoded_vec: TlsVec<ProtocolVersion, u8> = TlsVec::read(&mut buffer, &mut context).unwrap();

        assert_eq!(3, decoded_vec.len());
        assert_eq!(ProtocolVersion::tlsv1(), decoded_vec[0]);
        assert_eq!(ProtocolVersion::tlsv2(), decoded_vec[1]);
        assert_eq!(ProtocolVersion::tlsv3(), decoded_vec[2]);
    }

    #[test]
    fn test_encode_decode_tls_vec_u16() {
        use crate::ProtocolVersion;

        let mut buffer = Vec::new();

        let vec: TlsVec<ProtocolVersion, u16> = vec![
            ProtocolVersion::tlsv1(),
            ProtocolVersion::tlsv2(),
            ProtocolVersion::tlsv3(),
        ].into();

        let written = vec.write(&mut buffer).unwrap();
        assert_eq!(8, written);

        let mut buffer = Cursor::new(buffer);

        let mut context = Context::default();
        let decoded_vec: TlsVec<ProtocolVersion, u16> = TlsVec::read(&mut buffer, &mut context).unwrap();

        assert_eq!(3, decoded_vec.len());
        assert_eq!(ProtocolVersion::tlsv1(), decoded_vec[0]);
        assert_eq!(ProtocolVersion::tlsv2(), decoded_vec[1]);
        assert_eq!(ProtocolVersion::tlsv3(), decoded_vec[2]);
    }

    #[test]
    fn test_encode_decode_fixed_opaque() {
        let mut buffer = Vec::new();

        let opaque = FixedOpaque::new([ 0x13, 0x37 ]);

        let written = opaque.write(&mut buffer).unwrap();
        assert_eq!(2, written);

        let mut buffer = Cursor::new(buffer);

        let mut context = Context::default();
        let decoded_opaque: FixedOpaque<2> = FixedOpaque::read(&mut buffer, &mut context).unwrap();

        assert_eq!(2, decoded_opaque.0.len());
        assert_eq!(0x13, decoded_opaque.0[0]);
        assert_eq!(0x37, decoded_opaque.0[1]);
    }

    #[test]
    fn test_encode_decode_var_opaque_u8() {
        let mut buffer = Vec::new();

        let opaque: VarOpaque<u8> = vec![ 0x13, 0x37 ].into();

        let written = opaque.write(&mut buffer).unwrap();
        assert_eq!(3, written);

        let mut buffer = Cursor::new(buffer);

        let mut context = Context::default();
        let decoded_opaque: VarOpaque<u8> = VarOpaque::read(&mut buffer, &mut context).unwrap();

        assert_eq!(2, decoded_opaque.len());
        assert_eq!(0x13, decoded_opaque[0]);
        assert_eq!(0x37, decoded_opaque[1]);
    }

    #[test]
    fn test_encode_decode_var_opaque_u16() {
        let mut buffer = Vec::new();

        let opaque: VarOpaque<u16> = vec![ 0x13, 0x37 ].into();

        let written = opaque.write(&mut buffer).unwrap();
        assert_eq!(4, written);

        let mut buffer = Cursor::new(buffer);

        let mut context = Context::default();
        let decoded_opaque: VarOpaque<u16> = VarOpaque::read(&mut buffer, &mut context).unwrap();

        assert_eq!(2, decoded_opaque.len());
        assert_eq!(0x13, decoded_opaque[0]);
        assert_eq!(0x37, decoded_opaque[1]);
    }
}
