use std::{error::Error, fmt};

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
}

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashError::InvalidHexError => write!(f, "Invalid hexadecimal string provided"),
        }
    }
}

impl Error for HashError {}

#[derive(Clone, Debug)]
pub struct Message {
    buffer: Vec<u8>,
    bit_len: usize,
}

impl Message {
    pub fn new() -> Self {
        Self {
            buffer: vec![],
            bit_len: 0,
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
        self.bit_len = self.buffer.len() * 8;
        Ok(())
    }

    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
        self.bit_len = self.buffer.len() * 8;
    }

    pub fn extend_from_string(&mut self, message: &str) {
        self.buffer.extend_from_slice(message.as_bytes());
        self.bit_len = self.buffer.len() * 8;
    }

    pub fn from_hex(hex: &str) -> Result<Self, HashError> {
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
        let bit_len = buffer.len() * 8;
        Ok(Self { buffer, bit_len })
    }

    pub fn from_slice(bytes: &[u8]) -> Self {
        let buffer: Vec<u8> = bytes.to_vec();
        let bit_len: usize = buffer.len() * 8;
        Self { buffer, bit_len }
    }

    pub fn from_string(message: &str) -> Self {
        let buffer: Vec<u8> = message.as_bytes().to_vec();
        let bit_len: usize = buffer.len();
        Self { buffer, bit_len }
    }

    pub fn to_string(&self) -> String {
        self.buffer
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect()
    }

    // TODO: implement to_u64_le, to_u64_be, to_u32_le, to_u32_be
    // TODO: test Message: buffer and bit_len accessability
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex_string: String = self.to_string();
        write!(
            f,
            "Message: {} (bytes: {}, bits: {})",
            hex_string,
            self.bit_len / 8,
            self.bit_len
        )
    }
}

pub struct Input {
    bytes: Vec<u8>,
}

impl Input {
    pub fn from_string(msg: &str) -> Input {
        Input {
            bytes: msg.as_bytes().to_vec(),
        }
    }
}

pub struct Output {
    pub output: String,
}

impl Output {
    pub fn from_u8(output: Vec<u8>) -> Output {
        let output = output.iter().map(|byte| format!("{:02x}", byte)).collect();
        Output { output }
    }

    pub fn from_u32_le(output_u32: Vec<u32>) -> Output {
        let mut output_u8: Vec<u8> = Vec::new();
        for &value in &output_u32 {
            output_u8.extend_from_slice(&value.to_le_bytes());
        }
        Output::from_u8(output_u8)
    }

    pub fn from_u32_be(output_u32: Vec<u32>) -> Output {
        let mut output_u8: Vec<u8> = Vec::new();
        for &value in &output_u32 {
            output_u8.extend_from_slice(&value.to_be_bytes());
        }
        Output::from_u8(output_u8)
    }

    pub fn from_u64_be(output_u64: Vec<u64>) -> Output {
        let mut output_u8: Vec<u8> = Vec::new();
        for &value in &output_u64 {
            output_u8.extend_from_slice(&value.to_be_bytes());
        }
        Output::from_u8(output_u8)
    }

    pub fn from_u64_be_take_n_from_end(output_u64: &Vec<u64>, num_bytes: usize) -> Output {
        let mut output_u8: Vec<u8> = Vec::new();
        for &value in output_u64 {
            output_u8.extend_from_slice(&value.to_be_bytes());
        }
        Output::from_u8(output_u8[output_u8.len() - num_bytes..].to_vec())
    }

    pub fn from_u64_le(output_u64: Vec<u64>) -> Output {
        let mut output_u8: Vec<u8> = Vec::new();
        for &value in &output_u64 {
            output_u8.extend_from_slice(&value.to_le_bytes());
        }
        Output::from_u8(output_u8)
    }

    pub fn from_u64_le_drop_4_bytes(output_u64: Vec<u64>) -> Output {
        let mut output_u8: Vec<u8> = Vec::new();
        for &value in &output_u64 {
            output_u8.extend_from_slice(&value.to_le_bytes());
        }
        Output::from_u8(output_u8[..output_u8.len() - 4].to_vec())
    }
}
