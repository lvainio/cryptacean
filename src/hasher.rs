pub mod md5;

struct Input {
    bytes: Vec<u8>,
}

impl Input {
    fn from_vec(bytes: Vec<u8>) -> Input {
        Input { bytes }
    }

    fn from_slice(bytes: &[u8]) -> Input {
        Input {
            bytes: bytes.to_vec(),
        }
    }

    fn from_string(msg: String) -> Input {
        Input {
            bytes: msg.as_bytes().to_vec(),
        }
    }

    fn from_str(msg: &str) -> Input {
        Input {
            bytes: msg.as_bytes().to_vec(),
        }
    }
}

struct Output {
    output: String,
}

impl Output {
    fn from_u8(output: Vec<u8>) -> Output {
        let output = output.iter().map(|byte| format!("{:02x}", byte)).collect();
        Output { output }
    }

    fn from_u32_le(output_u32: Vec<u32>) -> Output {
        let mut output_u8: Vec<u8> = Vec::new();
        for &value in &output_u32 {
            output_u8.extend_from_slice(&value.to_le_bytes());
        }
        Output::from_u8(output_u8)
    }
}

trait HashFunction {
    fn hash(&self, input: &Input) -> Output;
}
