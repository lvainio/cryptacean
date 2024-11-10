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

#[derive(Clone)]
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

fn to_u64_vec_be(prev_message: Vec<u8>) -> Vec<u64> {
    // Ensure the length of prev_message is a multiple of 8
    assert!(
        prev_message.len() % 8 == 0,
        "Input length must be a multiple of 8"
    );

    // Convert Vec<u8> to Vec<u64>
    prev_message
        .chunks_exact(8) // Take 8 bytes at a time
        .map(|chunk| u64::from_be_bytes(chunk.try_into().unwrap())) // Convert each chunk to u64
        .collect() // Collect the u64 values into a Vec<u64>
}

fn to_u8_vec_be(words: Vec<u64>) -> Vec<u8> {
    words
        .iter() // Iterate over each u64
        .flat_map(|&word| word.to_be_bytes()) // Convert each u64 to [u8; 8] and flatten
        .collect() // Collect all bytes into a Vec<u8>
}

fn par(prev_message: Vec<u8>, d: usize, key: MD6Key, mode: usize, r: usize, level: u64) -> Vec<u8> {
    let prev_m = prev_message.len() * 8;
    let zero_bytes_to_add = 512 - (prev_message.len() % 512);
    let mut prev_message = prev_message.clone();
    prev_message.resize(prev_message.len() + zero_bytes_to_add, 0u8);

    let prev_message: Vec<u64> = to_u64_vec_be(prev_message);

    let mut new_message: Vec<u64> = Vec::new();

    let b = 4096;
    let j = (1).max(prev_m / (b * WORD_LENGTH));
    for i in 0..j {
        // STEP 1
        let mut p = 0;
        if i == j - 1 {
            p = zero_bytes_to_add * 8;
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
        input[10..].copy_from_slice(&prev_message[i * 64..((i + 1) * 64)]);

        let chunk: [u64; 16] = compress(&input, r);

        new_message.extend_from_slice(&chunk);
    }
    let new_message = to_u8_vec_be(new_message);
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

    pub fn hash(&self, input: &Input) -> Output {
        let input: Vec<u8> = input.bytes.clone();
        let d: usize = self.d;
        let key: MD6Key = self.key.clone();
        let mode: usize = self.mode as usize;
        let r: usize = self.r;
        let c: usize = 16;

        let mut level = 0;
        let mut m_curr = input.len() * 8;

        level += 1;
        let mut new_message: Vec<u8> = par(input.clone(), d, key.clone(), mode, r, level);
        while new_message.len() * 8 != c * WORD_LENGTH {
            level += 1;
            new_message = par(input.clone(), d, key.clone(), mode, r, level);
        }

        let d_bytes = d / 8;
        Output::from_u8(new_message[new_message.len() - d_bytes..].to_vec())
    }
}

pub struct MD6_160 {
    md6: MD6,
}

impl MD6_160 {
    pub fn new() -> Self {
        Self { md6: MD6::new(160) }
    }

    pub fn hash(&self, input: &Input) -> Output {
        self.md6.hash(input)
    }
}

pub struct MD6_224 {
    md6: MD6,
}

impl MD6_224 {
    pub fn new() -> Self {
        Self { md6: MD6::new(224) }
    }

    pub fn hash(&self, input: &Input) -> Output {
        self.md6.hash(input)
    }
}

pub struct MD6_256 {
    md6: MD6,
}

impl MD6_256 {
    pub fn new() -> Self {
        Self { md6: MD6::new(256) }
    }

    pub fn hash(&self, input: &Input) -> Output {
        self.md6.hash(input)
    }
}

pub struct MD6_384 {
    md6: MD6,
}

impl MD6_384 {
    pub fn new() -> Self {
        Self { md6: MD6::new(384) }
    }

    pub fn hash(&self, input: &Input) -> Output {
        self.md6.hash(input)
    }
}

pub struct MD6_512 {
    md6: MD6,
}

impl MD6_512 {
    pub fn new() -> Self {
        Self { md6: MD6::new(512) }
    }

    pub fn hash(&self, input: &Input) -> Output {
        self.md6.hash(input)
    }
}

// TODO: Implement SEQ and tests
// TODO: Implement test case for general version if opssible
// TODO: Clean up ugly code. Remove unused vars.
// TODO: Documentation.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md6_160_works() {
        let md6_160 = MD6_160::new();
        let i1 = Input::from_string("");
        let i2 = Input::from_string("abc");
        assert_eq!(
            md6_160.hash(&i1).output,
            "f325ee93c54cfaacd7b9007e1cf8904680993b18"
        );
        assert_eq!(
            md6_160.hash(&i2).output,
            "b5c2d6a7ce6be0c18c9a38b17a0db705c81ab6b5"
        );
    }

    #[test]
    fn md6_224_works() {
        let md6_224 = MD6_224::new();
        let i1 = Input::from_string("");
        let i2 = Input::from_string("abc");
        assert_eq!(
            md6_224.hash(&i1).output,
            "d2091aa2ad17f38c51ade2697f24cafc3894c617c77ffe10fdc7abcb"
        );
        assert_eq!(
            md6_224.hash(&i2).output,
            "510c30e4202a5cdd8a4f2ae9beebb6f5988128897937615d52e6d228"
        );
    }

    #[test]
    fn md6_256_works() {
        let md6_256 = MD6_256::new();
        let i1 = Input::from_string("");
        let i2 = Input::from_string("abc");
        assert_eq!(
            md6_256.hash(&i1).output,
            "bca38b24a804aa37d821d31af00f5598230122c5bbfc4c4ad5ed40e4258f04ca"
        );
        assert_eq!(
            md6_256.hash(&i2).output,
            "230637d4e6845cf0d092b558e87625f03881dd53a7439da34cf3b94ed0d8b2c5"
        );
    }

    #[test]
    fn md6_384_works() {
        let md6_384 = MD6_384::new();
        let i1 = Input::from_string("");
        let i2 = Input::from_string("abc");
        assert_eq!(
            md6_384.hash(&i1).output,
            "b0bafffceebe856c1eff7e1ba2f539693f828b532ebf60ae9c16cbc3499020401b942ac25b310b2227b2954ccacc2f1f"
        );
        assert_eq!(
            md6_384.hash(&i2).output,
            "e2c6d31dd8872cbd5a1207481cdac581054d13a4d4fe6854331cd8cf3e7cbafbaddd6e2517972b8ff57cdc4806d09190"
        );
    }

    #[test]
    fn md6_512_works() {
        let md6_512 = MD6_512::new();
        let i1 = Input::from_string("");
        let i2 = Input::from_string("abc");
        assert_eq!(md6_512.hash(&i1).output, "6b7f33821a2c060ecdd81aefddea2fd3c4720270e18654f4cb08ece49ccb469f8beeee7c831206bd577f9f2630d9177979203a9489e47e04df4e6deaa0f8e0c0");
        assert_eq!(md6_512.hash(&i2).output, "00918245271e377a7ffb202b90f3bda5477d8feab12d8a3a8994ebc55fe6e74ca8341520032eeea3fdef892f2882378f636212af4b2683ccf80bf025b7d9b457");
    }
}
