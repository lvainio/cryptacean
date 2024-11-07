use clap::ValueEnum;

pub mod md;
pub mod sha;

use md::{md2, md4, md5};
use sha::{sha0, sha1, sha224, sha256, sha384, sha3_224, sha3_256, sha512, sha512_224, sha512_256};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum HashType {
    MD2,
    MD4,
    MD5,
    SHA0,
    SHA1,
    SHA3_224,
    SHA3_256,
    SHA224,
    SHA256,
    SHA384,
    SHA512_224,
    SHA512_256,
    SHA512,
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

pub trait HashFunction {
    fn hash(&self, input: &Input) -> Output;
}

pub struct Hasher {
    hash_func: Box<dyn HashFunction>,
}

impl Hasher {
    pub fn new(hashtype: HashType) -> Self {
        let hash_func: Box<dyn HashFunction> = match hashtype {
            HashType::MD2 => Box::new(md2::MD2),
            HashType::MD4 => Box::new(md4::MD4),
            HashType::MD5 => Box::new(md5::MD5),
            HashType::SHA0 => Box::new(sha0::SHA0),
            HashType::SHA1 => Box::new(sha1::SHA1),
            HashType::SHA3_224 => Box::new(sha3_224::SHA3_224),
            HashType::SHA3_256 => Box::new(sha3_256::SHA3_256),
            HashType::SHA256 => Box::new(sha256::SHA256),
            HashType::SHA224 => Box::new(sha224::SHA224),
            HashType::SHA384 => Box::new(sha384::SHA384),
            HashType::SHA512 => Box::new(sha512::SHA512),
            HashType::SHA512_224 => Box::new(sha512_224::SHA512_224),
            HashType::SHA512_256 => Box::new(sha512_256::SHA512_256),
        };
        Hasher { hash_func }
    }

    pub fn run(&self, words: &String, digest: &String) {
        for word in words.lines() {
            let input = Input::from_string(word);

            let output = self.hash_func.hash(&input).output;

            if *digest == output {
                println!("found match: {word}");
                println!("hash(word) = {output}");
                println!("digest = {digest}");
                break;
            }
        }
    }
}
