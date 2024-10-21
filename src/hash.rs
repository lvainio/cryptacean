use clap::ValueEnum;

pub mod md4;
pub mod md5;
pub mod sha1;
pub mod sha224;
pub mod sha256;
pub mod sha384;
pub mod sha512;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum HashType {
    MD4,
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
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
            HashType::MD4 => Box::new(md4::MD4),
            HashType::MD5 => Box::new(md5::MD5),
            HashType::SHA1 => Box::new(sha1::SHA1),
            HashType::SHA256 => Box::new(sha256::SHA256),
            HashType::SHA224 => Box::new(sha224::SHA224),
            HashType::SHA384 => Box::new(sha384::SHA384),
            HashType::SHA512 => Box::new(sha512::SHA512),
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
