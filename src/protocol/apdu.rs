use core::fmt;
use std::{convert::TryInto, error::Error};

/// cbindgen:ignore
mod iso7816 {
    pub const OFFSET_P1: usize = 2;
    pub const OFFSET_P2: usize = 3;
    pub const OFFSET_LC: usize = 4;

    pub const SW_NO_ERROR: u16 = 0x9000;
}

pub struct CommandBuilder {
    apdu: Vec<u8>,
}

impl CommandBuilder {
    pub fn new(cla: u8, ins: u8) -> Self {
        Self {
            apdu: vec![cla, ins, 0, 0],
        }
    }

    pub fn p1(mut self, val: u8) -> Self {
        self.apdu[iso7816::OFFSET_P1] = val;
        self
    }

    pub fn p2(mut self, val: u8) -> Self {
        self.apdu[iso7816::OFFSET_P2] = val;
        self
    }

    pub fn push(self, val: u8) -> Self {
        self.extend(&[val])
    }

    pub fn extend(mut self, data: &[u8]) -> Self {
        if iso7816::OFFSET_LC >= self.apdu.len() {
            self.apdu.push(0);
        }
        self.apdu.extend_from_slice(data);
        self.apdu[iso7816::OFFSET_LC] += data.len() as u8;
        self
    }

    pub fn build(self) -> Vec<u8> {
        self.apdu
    }
}

#[derive(Debug)]
pub struct CardError {
    status: u16,
}

impl fmt::Display for CardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "card returned error status {:#x}", self.status)
    }
}

impl Error for CardError {}

pub fn parse_response(raw: &[u8]) -> Result<&[u8], CardError> {
    let (data, status) = raw.split_at(raw.len() - 2);
    let status = u16::from_be_bytes(status.try_into().unwrap());
    match status {
        iso7816::SW_NO_ERROR => Ok(data),
        _ => Err(CardError { status }),
    }
}
