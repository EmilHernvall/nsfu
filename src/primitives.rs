use bytes::{Buf, BufMut};

use crate::{
    Result,
    Error,
    ReadablePacketFragment,
    WritablePacketFragment,
    Context,
};

#[allow(non_camel_case_types)]
pub struct u24(pub u32);

impl ReadablePacketFragment for u8 {
    fn read<B: Buf>(buffer: &mut B, _ctx: &mut Context) -> Result<Self> {
        if !buffer.has_remaining() {
            return Err(Error::EOF);
        }

        Ok(buffer.get_u8())
    }
}

impl WritablePacketFragment for u8 {
    fn written_length(&self) -> usize {
        1
    }

    fn write<B: BufMut>(&self, buffer: &mut B) -> Result<usize> {
        buffer.put_u8(*self);
        Ok(1)
    }
}

impl ReadablePacketFragment for u16 {
    fn read<B: Buf>(buffer: &mut B, _ctx: &mut Context) -> Result<Self> {
        if buffer.remaining() < 2 {
            return Err(Error::EOF);
        }

        Ok(buffer.get_u16())
    }
}

impl WritablePacketFragment for u16 {
    fn written_length(&self) -> usize {
        2
    }

    fn write<B: BufMut>(&self, buffer: &mut B) -> Result<usize> {
        buffer.put_u16(*self);
        Ok(2)
    }
}

impl ReadablePacketFragment for u24 {
    fn read<B: Buf>(buffer: &mut B, ctx: &mut Context) -> Result<Self> {
        let a = u8::read(buffer, ctx)? as u32;
        let b = u8::read(buffer, ctx)? as u32;
        let c = u8::read(buffer, ctx)? as u32;

        Ok(u24((a << 16) | (b << 8) | c))
    }
}

impl WritablePacketFragment for u24 {
    fn written_length(&self) -> usize {
        3
    }

    fn write<B: BufMut>(&self, buffer: &mut B) -> Result<usize> {
        let [_, a, b, c] = self.0.to_be_bytes();
        buffer.put_u8(a);
        buffer.put_u8(b);
        buffer.put_u8(c);
        Ok(3)
    }
}

#[derive(Clone, Debug)]
pub struct TlsVec<T, const N: usize>(pub Vec<T>);

impl<T, const N: usize> From<Vec<T>> for TlsVec<T, N> {
    fn from(v: Vec<T>) -> Self {
        TlsVec(v)
    }
}

impl<T: ReadablePacketFragment> ReadablePacketFragment for TlsVec<T, 1> {
    fn read<B: Buf>(buffer: &mut B, ctx: &mut Context) -> Result<Self> {
        let len = u8::read(buffer, ctx)?;

        let target = buffer.remaining() - len as usize;
        let mut vec = Vec::new();
        while buffer.remaining() > target {
            vec.push(T::read(buffer, ctx)?);
        }

        Ok(TlsVec(vec))
    }
}

impl<T: ReadablePacketFragment> ReadablePacketFragment for TlsVec<T, 2> {
    fn read<B: Buf>(buffer: &mut B, ctx: &mut Context) -> Result<Self> {
        let len = u16::read(buffer, ctx)?;

        let target = buffer.remaining() - len as usize;
        let mut vec = Vec::new();
        while buffer.remaining() > target {
            vec.push(T::read(buffer, ctx)?);
        }

        Ok(TlsVec(vec))
    }
}

impl<T: WritablePacketFragment> WritablePacketFragment for TlsVec<T, 1> {
    fn written_length(&self) -> usize {
        1 + self.0.iter().map(|x| x.written_length()).sum::<usize>()
    }

    fn write<B: BufMut>(&self, buffer: &mut B) -> Result<usize> {
        let mut written = 1;
        let len = self.written_length() - 1;
        if len >= 0xFF {
            return Err(Error::Overflow);
        }

        buffer.put_u8(len as u8);

        for element in &self.0 {
            written += element.write(buffer)?;
        }

        Ok(written)
    }
}

impl<T: WritablePacketFragment> WritablePacketFragment for TlsVec<T, 2> {
    fn written_length(&self) -> usize {
        2 + self.0.iter().map(|x| x.written_length()).sum::<usize>()
    }

    fn write<B: BufMut>(&self, buffer: &mut B) -> Result<usize> {
        let mut written = 2;

        let len = self.written_length() - 2;
        if len >= 0xFFFF {
            return Err(Error::Overflow);
        }

        buffer.put_u16(len as u16);

        for element in &self.0 {
            written += element.write(buffer)?;
        }

        Ok(written)
    }
}

#[derive(Clone, Debug)]
pub struct FixedOpaque<const N: usize>(pub [u8; N]);

impl<const N: usize> FixedOpaque<N> {
    pub fn new(v: [u8; N]) -> Self {
        FixedOpaque(v)
    }
}

impl<const N: usize> ReadablePacketFragment for FixedOpaque<N> {
    fn read<B: Buf>(buffer: &mut B, _ctx: &mut Context) -> Result<Self> {
        if buffer.remaining() < N {
            return Err(Error::EOF);
        }
        let mut vec = [0; N];
        buffer.copy_to_slice(&mut vec);
        Ok(FixedOpaque(vec))
    }
}

impl<const N: usize> WritablePacketFragment for FixedOpaque<N> {
    fn written_length(&self) -> usize {
        self.0.len()
    }

    fn write<B: BufMut>(&self, buffer: &mut B) -> Result<usize> {
        buffer.put_slice(&self.0);
        Ok(N)
    }
}

#[derive(Clone, Debug)]
pub struct VarOpaque<const N: usize>(pub Vec<u8>);

impl<T, const N: usize> From<T> for VarOpaque<N> where T: AsRef<[u8]> {
    fn from(v: T) -> Self {
        VarOpaque(v.as_ref().iter().cloned().collect())
    }
}

impl ReadablePacketFragment for VarOpaque<1> {
    fn read<B: Buf>(buffer: &mut B, ctx: &mut Context) -> Result<Self> {
        let len = u8::read(buffer, ctx)? as usize;
        if buffer.remaining() < len {
            return Err(Error::EOF);
        }
        let mut vec = vec![0; len];
        buffer.copy_to_slice(&mut vec);
        Ok(VarOpaque(vec))
    }
}

impl ReadablePacketFragment for VarOpaque<2> {
    fn read<B: Buf>(buffer: &mut B, ctx: &mut Context) -> Result<Self> {
        let len = u16::read(buffer, ctx)? as usize;
        if buffer.remaining() < len {
            return Err(Error::EOF);
        }
        let mut vec = vec![0; len];
        buffer.copy_to_slice(&mut vec);
        Ok(VarOpaque(vec))
    }
}

impl ReadablePacketFragment for VarOpaque<3> {
    fn read<B: Buf>(buffer: &mut B, ctx: &mut Context) -> Result<Self> {
        let len = u24::read(buffer, ctx)?.0 as usize;
        if buffer.remaining() < len {
            return Err(Error::EOF);
        }
        let mut vec = vec![0; len];
        buffer.copy_to_slice(&mut vec);
        Ok(VarOpaque(vec))
    }
}

impl WritablePacketFragment for VarOpaque<1> {
    fn written_length(&self) -> usize {
        1 + self.0.len()
    }

    fn write<B: BufMut>(&self, buffer: &mut B) -> Result<usize> {
        if self.0.len() >= 0xFF {
            return Err(Error::Overflow);
        }
        buffer.put_u8(self.0.len() as u8);
        buffer.put_slice(&self.0);
        Ok(1 + self.0.len())
    }
}

impl WritablePacketFragment for VarOpaque<2> {
    fn written_length(&self) -> usize {
        2 + self.0.len()
    }

    fn write<B: BufMut>(&self, buffer: &mut B) -> Result<usize> {
        if self.0.len() >= 0xFFFF {
            return Err(Error::Overflow);
        }
        buffer.put_u16(self.0.len() as u16);
        buffer.put_slice(&self.0);
        Ok(2 + self.0.len())
    }
}

impl WritablePacketFragment for VarOpaque<3> {
    fn written_length(&self) -> usize {
        3 + self.0.len()
    }

    fn write<B: BufMut>(&self, buffer: &mut B) -> Result<usize> {
        if self.0.len() >= 0xFFFF {
            return Err(Error::Overflow);
        }
        u24(self.0.len() as u32).write(buffer)?;
        buffer.put_slice(&self.0);
        Ok(2 + self.0.len())
    }
}

#[cfg(test)]
pub mod tests {
    use bytes::BytesMut;

    use super::*;

    #[test]
    fn test_encode_decode_tls_vec_u8() {
        use crate::ProtocolVersion;

        let mut buffer = BytesMut::new();

        let vec: TlsVec<ProtocolVersion, 1> = vec![
            ProtocolVersion::tlsv1(),
            ProtocolVersion::tlsv2(),
            ProtocolVersion::tlsv3(),
        ].into();

        let written = vec.write(&mut buffer).unwrap();
        assert_eq!(7, written);

        let mut context = Context::default();
        let decoded_vec: TlsVec<ProtocolVersion, 1> = TlsVec::read(&mut buffer, &mut context).unwrap();

        assert_eq!(3, decoded_vec.0.len());
        assert_eq!(ProtocolVersion::tlsv1(), decoded_vec.0[0]);
        assert_eq!(ProtocolVersion::tlsv2(), decoded_vec.0[1]);
        assert_eq!(ProtocolVersion::tlsv3(), decoded_vec.0[2]);
    }

    #[test]
    fn test_encode_decode_tls_vec_u16() {
        use crate::ProtocolVersion;

        let mut buffer = BytesMut::new();

        let vec: TlsVec<ProtocolVersion, 2> = vec![
            ProtocolVersion::tlsv1(),
            ProtocolVersion::tlsv2(),
            ProtocolVersion::tlsv3(),
        ].into();

        let written = vec.write(&mut buffer).unwrap();
        assert_eq!(8, written);

        let mut context = Context::default();
        let decoded_vec: TlsVec<ProtocolVersion, 2> = TlsVec::read(&mut buffer, &mut context).unwrap();

        assert_eq!(3, decoded_vec.0.len());
        assert_eq!(ProtocolVersion::tlsv1(), decoded_vec.0[0]);
        assert_eq!(ProtocolVersion::tlsv2(), decoded_vec.0[1]);
        assert_eq!(ProtocolVersion::tlsv3(), decoded_vec.0[2]);
    }

    #[test]
    fn test_encode_decode_fixed_opaque() {
        let mut buffer = BytesMut::new();

        let opaque = FixedOpaque::new([ 0x13, 0x37 ]);

        let written = opaque.write(&mut buffer).unwrap();
        assert_eq!(2, written);

        let mut context = Context::default();
        let decoded_opaque: FixedOpaque<2> = FixedOpaque::read(&mut buffer, &mut context).unwrap();

        assert_eq!(2, decoded_opaque.0.len());
        assert_eq!(0x13, decoded_opaque.0[0]);
        assert_eq!(0x37, decoded_opaque.0[1]);
    }

    #[test]
    fn test_encode_decode_var_opaque_u8() {
        let mut buffer = BytesMut::new();

        let opaque: VarOpaque<1> = vec![ 0x13, 0x37 ].into();

        let written = opaque.write(&mut buffer).unwrap();
        assert_eq!(3, written);

        let mut context = Context::default();
        let decoded_opaque: VarOpaque<1> = VarOpaque::read(&mut buffer, &mut context).unwrap();

        assert_eq!(2, decoded_opaque.0.len());
        assert_eq!(0x13, decoded_opaque.0[0]);
        assert_eq!(0x37, decoded_opaque.0[1]);
    }

    #[test]
    fn test_encode_decode_var_opaque_u16() {
        let mut buffer = BytesMut::new();

        let opaque: VarOpaque<2> = vec![ 0x13, 0x37 ].into();

        let written = opaque.write(&mut buffer).unwrap();
        assert_eq!(4, written);

        let mut context = Context::default();
        let decoded_opaque: VarOpaque<2> = VarOpaque::read(&mut buffer, &mut context).unwrap();

        assert_eq!(2, decoded_opaque.0.len());
        assert_eq!(0x13, decoded_opaque.0[0]);
        assert_eq!(0x37, decoded_opaque.0[1]);
    }
}
