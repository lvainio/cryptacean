use std::{error, fmt, ops};

pub mod md2;
pub mod md4;
pub mod md5;
pub mod md6;

pub mod sha0;
pub mod sha1;
pub mod sha224;
pub mod sha256;
pub mod sha3;
pub mod sha384;
pub mod sha512;
pub mod sha512_224;
pub mod sha512_256;

#[derive(Debug)]
pub enum HashError {
    InvalidHexError,
    RangeOutOfBoundsError,
}

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashError::InvalidHexError => write!(f, "Invalid hexadecimal string provided"),
            HashError::RangeOutOfBoundsError => write!(f, "Provided range is out of bounds"),
        }
    }
}

impl error::Error for HashError {}

pub enum Endianness {
    Big,
    Little,
}

#[derive(Clone, Debug)]
pub struct Message {
    buffer: Vec<u8>,
    message_size: usize,
}

impl Message {
    pub fn new() -> Self {
        Self {
            buffer: vec![],
            message_size: 0,
        }
    }

    pub fn extend_from_hex(&mut self, hex: &str) -> Result<(), HashError> {
        if hex.len() % 2 != 0 {
            return Err(HashError::InvalidHexError);
        }
        let mut buffer = Vec::new();
        for i in (0..hex.len()).step_by(2) {
            let byte_str = &hex[i..i + 2];
            match u8::from_str_radix(byte_str, 16) {
                Ok(byte) => buffer.push(byte),
                Err(_) => return Err(HashError::InvalidHexError),
            }
        }
        self.message_size = self.buffer.len() * 8;
        Ok(())
    }

    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
        self.message_size = self.buffer.len() * 8;
    }

    pub fn extend_from_string(&mut self, message: &str) {
        self.buffer.extend_from_slice(message.as_bytes());
        self.message_size = self.buffer.len() * 8;
    }

    pub fn from_hex(message: &str) -> Result<Self, HashError> {
        if message.len() % 2 != 0 {
            return Err(HashError::InvalidHexError);
        }
        let mut buffer = Vec::new();
        for i in (0..message.len()).step_by(2) {
            let byte_str = &message[i..i + 2];
            match u8::from_str_radix(byte_str, 16) {
                Ok(byte) => buffer.push(byte),
                Err(_) => return Err(HashError::InvalidHexError),
            }
        }
        let message_size = buffer.len() * 8;
        Ok(Self {
            buffer,
            message_size,
        })
    }

    pub fn from_slice(message: &[u8]) -> Self {
        let buffer: Vec<u8> = message.to_vec();
        let message_size: usize = buffer.len() * 8;
        Self {
            buffer,
            message_size,
        }
    }

    pub fn from_string(message: &str) -> Self {
        let buffer: Vec<u8> = message.as_bytes().to_vec();
        let message_size: usize = buffer.len();
        Self {
            buffer,
            message_size,
        }
    }

    pub fn to_hex(&self) -> String {
        self.buffer
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect()
    }

    pub fn to_slice(&self) -> &[u8] {
        &self.buffer
    }

    pub fn to_string(&self) -> String {
        self.buffer
            .iter()
            .map(|byte| format!("0x{byte:02x}, "))
            .collect::<Vec<String>>()
            .join("")
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex_string: String = self.to_hex();
        write!(
            f,
            "Message: {} (bytes: {}, bits: {})",
            hex_string,
            self.message_size / 8,
            self.message_size
        )
    }
}

#[derive(Clone, Debug)]
pub struct Digest {
    buffer: Vec<u8>,
    digest_size: usize,
}

impl Digest {
    pub fn from_u8(digest: &[u8]) -> Self {
        let buffer: Vec<u8> = digest.to_vec();
        let digest_size: usize = buffer.len() * 8;
        Self {
            buffer,
            digest_size,
        }
    }

    pub fn from_u32(digest_u32: &[u32], endianness: Endianness) -> Self {
        let mut digest_u8: Vec<u8> = vec![];
        for &value in digest_u32 {
            match endianness {
                Endianness::Big => digest_u8.extend_from_slice(&value.to_be_bytes()),
                Endianness::Little => digest_u8.extend_from_slice(&value.to_le_bytes()),
            }
        }
        Self::from_u8(&digest_u8)
    }

    pub fn from_u32_range(
        digest_u32: &[u32],
        endianness: Endianness,
        byte_range: ops::Range<usize>,
    ) -> Result<Self, HashError> {
        let mut digest_u8: Vec<u8> = vec![];
        for &value in digest_u32 {
            match endianness {
                Endianness::Big => digest_u8.extend_from_slice(&value.to_be_bytes()),
                Endianness::Little => digest_u8.extend_from_slice(&value.to_le_bytes()),
            }
        }
        if byte_range.start > byte_range.end
            || byte_range.start >= digest_u8.len()
            || byte_range.end > digest_u8.len()
        {
            return Err(HashError::RangeOutOfBoundsError);
        }
        Ok(Self::from_u8(&digest_u8[byte_range]))
    }

    pub fn from_u64(digest_u64: &[u64], endianness: Endianness) -> Self {
        let mut digest_u8: Vec<u8> = vec![];
        for &value in digest_u64 {
            match endianness {
                Endianness::Big => digest_u8.extend_from_slice(&value.to_be_bytes()),
                Endianness::Little => digest_u8.extend_from_slice(&value.to_le_bytes()),
            }
        }
        Self::from_u8(&digest_u8)
    }

    pub fn from_u64_range(
        digest_u64: &[u64],
        endianness: Endianness,
        byte_range: ops::Range<usize>,
    ) -> Result<Self, HashError> {
        let mut digest_u8: Vec<u8> = vec![];
        for &value in digest_u64 {
            match endianness {
                Endianness::Big => digest_u8.extend_from_slice(&value.to_be_bytes()),
                Endianness::Little => digest_u8.extend_from_slice(&value.to_le_bytes()),
            }
        }
        if byte_range.start > byte_range.end
            || byte_range.start >= digest_u8.len()
            || byte_range.end > digest_u8.len()
        {
            return Err(HashError::RangeOutOfBoundsError);
        }
        Ok(Self::from_u8(&digest_u8[byte_range]))
    }

    pub fn to_hex(&self) -> String {
        self.buffer
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect()
    }

    pub fn to_slice(&self) -> &[u8] {
        &self.buffer
    }

    pub fn to_string(&self) -> String {
        self.buffer
            .iter()
            .map(|byte| format!("0x{byte:02x}, "))
            .collect::<Vec<String>>()
            .join("")
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex_string: String = self.to_hex();
        write!(
            f,
            "Digest: {} (bytes: {}, bits: {})",
            hex_string,
            self.digest_size / 8,
            self.digest_size
        )
    }
}
