/// A module which contains extensions for working with the bytes crate without
/// risking a panic. We encapsulate this in a separate module so we can avoid
/// importing the Buf and BufMut traits in the actual protocol parser, where
/// we might accidentally invoke one of the panicking methods.

use super::{Error, Result};
use bytes::Buf;

// network byte order = big endian

pub trait BufExt: Buf {
    fn remaining_bytes(&self) -> usize {
        Buf::remaining(self)
    }

    fn read_slice(&mut self, slice: &mut [u8]) -> Result<()> {
        if self.remaining() < slice.len() {
            return Err(Error::EOF);
        }

        self.copy_to_slice(slice);

        Ok(())
    }

    fn read_u8(&mut self) -> Result<u8> {
        if !self.has_remaining() {
            return Err(Error::EOF);
        }

        Ok(self.get_u8())
    }

    fn read_u16(&mut self) -> Result<u16> {
        if self.remaining() < 2 {
            return Err(Error::EOF);
        }

        Ok(self.get_u16())
    }

    fn read_u24(&mut self) -> Result<u32> {
        let a = self.read_u8()? as u32;
        let b = self.read_u8()? as u32;
        let c = self.read_u8()? as u32;

        Ok((a << 16) | (b << 8) | c)
    }
}

impl<T> BufExt for T where T: Buf {}
