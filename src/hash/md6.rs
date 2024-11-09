use std::fmt;

use crate::hash::{Input, Output};

const WORD_LENGTH: usize = 64;

const Q: [u64; 15] = [
    0x7311c2812425cfa0,
    0x6432286434aac8e7,
    0xb60450e9ef68b7c1,
    0xe8fb23908d9f06f1,
    0xdd2e76cba691e5bf,
    0x0cd0d63b2c30bc41,
    0x1f8ccf6823058f8a,
    0x54e5ed5b88e3775d,
    0x4ad12aae0a6d6031,
    0x3e7f16bb88222e0d,
    0x8af8671d3fb50c2c,
    0x995ad1178bd25c31,
    0xc878c1dd04c4b633,
    0x3b72066c7a1552ac,
    0x0d6f3522631effcb,
];

const T0: usize = 17;
const T1: usize = 18;
const T2: usize = 21;
const T3: usize = 31;
const T4: usize = 67;

const RIGHT_SHIFTS: [usize; 16] = [10, 5, 13, 10, 11, 12, 2, 7, 14, 15, 7, 13, 11, 7, 6, 12];
const LEFT_SHIFTS: [usize; 16] = [11, 24, 9, 16, 15, 9, 27, 15, 6, 2, 29, 8, 15, 5, 31, 9];

const S_PRIM_0: u64 = 0x0123456789abcdef;
const S_STAR: u64 = 0x7311c2812425cfa0;

#[derive(Debug)]
struct MD6KeyError;

impl fmt::Display for MD6KeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Key length exceeds maximum allowable size of 64 bytes.")
    }
}

pub struct MD6Key {
    key: Vec<u64>,
    key_len: usize,
}

impl MD6Key {
    pub fn new(key: Option<Vec<u8>>) -> Result<Self, MD6KeyError> {
        const MAX_LEN: usize = 64;
        match key {
            None => Ok(Self {
                key: vec![0; 8],
                key_len: 0,
            }),
            Some(key) => {
                if key.len() > MAX_LEN {
                    return Err(MD6KeyError);
                } else {
                    let mut key = key.clone();
                    let key_len = key.len();
                    key.resize(64, 0u8);
                    let key: Vec<u64> = key
                        .chunks_exact(8)
                        .map(|chunk| u64::from_be_bytes(chunk.try_into().unwrap()))
                        .collect();
                    Ok(Self { key, key_len })
                }
            }
        }
    }
}

fn compress(input: &[u64; 74], r: usize) -> [u64; 16] {
    let c: usize = 16;
    let n: usize = 89;
    let t: usize = r * c;

    let mut a_vec: Vec<u64> = Vec::with_capacity(n);
    a_vec.extend_from_slice(&Q);
    a_vec.extend_from_slice(input);

    let mut s_vec: Vec<u64> = vec![S_PRIM_0];
    for i in 1..r {
        s_vec.push(s_vec[i - 1].rotate_left(1) ^ (s_vec[i - 1] & S_STAR));
    }

    for i in n..(t + n) {
        let mut x = s_vec[(i - n) / 16] ^ a_vec[i - n] ^ a_vec[i - T0];
        x ^= (a_vec[i - T1] & a_vec[i - T2]) ^ (a_vec[i - T3] & a_vec[i - T4]);
        x ^= x >> RIGHT_SHIFTS[(i - n) % 16];
        a_vec.push(x ^ (x << LEFT_SHIFTS[(i - n) % 16]));
    }

    let mut chaining_value = [0u64; 16];
    chaining_value.copy_from_slice(&a_vec[a_vec.len() - 16..]);
    chaining_value
}

fn construct_v(r: usize, mode: usize, z: u64, p: usize, key_len: usize, d: usize) -> u64 {
    // 4 most significant bits should be 0000
    let mut v: u64 = 0x0;

    // next 12 bits should be r
    v |= (r as u64) << 48;

    // next 8 bits should be mode/L
    v |= (mode as u64) << 40;

    // next 4 bits should be z
    v |= z << 36;

    // next 16 bits should be p
    v |= (p as u64) << 20;

    // next 8 bits should be key_len
    v |= (key_len as u64) << 12;

    // 12 least significant bits should b d
    v |= d as u64;

    v
}

fn par(
    prev_message: Vec<u64>,
    d: usize,
    key: MD6Key,
    mode: usize,
    r: usize,
    level: u64,
) -> Vec<u64> {
    let prev_m = prev_message.len() * WORD_LENGTH;
    let zero_words_to_add = 64 - (prev_message.len() % 64);
    let mut prev_message = prev_message.clone();
    prev_message.resize(prev_message.len() + zero_words_to_add, 0u64);

    let mut new_message: Vec<u64> = Vec::new();

    let b = 4096;
    let j = (1).max(prev_m / (b * WORD_LENGTH));
    for i in 0..j {
        // STEP 1
        let mut p = 0;
        if i == j - 1 {
            p = zero_words_to_add * WORD_LENGTH;
        }

        // STEP 2
        let z: u64 = if j == 1 { 1 } else { 0 };

        // STEP 3 - construct V function
        let v: u64 = construct_v(r, mode, z, p, key.key_len, d);

        // Step 4 - construct U
        let u: u64 = level * 2u64.pow(56) + i as u64;

        // Step 5 - combine values and call compress, appedn to new_message
        let mut input: [u64; 74] = [0; 74];
        input[..8].copy_from_slice(&key.key.as_slice()); // key
        input[8] = u; // u
        input[9] = v; // v
        input[10..].copy_from_slice(&prev_message[i*64..((i+1)*64)]);

        let chunk: [u64; 16] = compress(&input, r);

        new_message.extend_from_slice(&chunk);
    }
    new_message
}

pub struct MD6 {
    d: usize,     // (output length in bits, 1..=512)
    key: MD6Key, // Optional (not sure what happens when null yet so lets keep it like this for now TODO:)
    mode: u64,   // 0..=64 Optional but has a default value so should NOT be an Option
    r: usize,    // (number of rounds)
    level: usize, // tree level
}

impl MD6 {
    pub fn new(d: usize) -> Self {
        Self {
            d,
            key: MD6Key::new(None).unwrap(),
            mode: 64,
            r: 40 + (d / 4),
            level: 0,
        }
    }

    pub fn with_key(mut self, key: MD6Key) -> Self {
        self.key = key;
        self
    }

    pub fn with_mode(mut self, mode: u64) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_rounds(mut self, r: usize) -> Self {
        self.r = r;
        self
    }
}

impl MD6 {
    pub fn hash(&self, input: &Input) -> Output {
        let input: Vec<u32> = vec![];

        Output::from_u32_le(vec![])
    }
}

// TODO: Implement general MD6 (byte level version)
// TODO: Implement MD6_160, MD6_224, MD6_256, MD6_384, MD6_512
// TODO: Implement test cases for each major version

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md6_160_works() {}

    #[test]
    fn md6_224_works() {}

    #[test]
    fn md6_256_works() {}

    #[test]
    fn md6_384_works() {}

    #[test]
    fn md6_512_works() {}
}
