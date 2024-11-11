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

pub use md2::MD2;
pub use md4::MD4;
pub use md5::MD5;

pub use sha0::SHA0;
pub use sha1::SHA1;
pub use sha224::SHA224;
pub use sha256::SHA256;
pub use sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};
pub use sha384::SHA384;
pub use sha512::SHA512;
pub use sha512_224::SHA512_224;
pub use sha512_256::SHA512_256;

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
