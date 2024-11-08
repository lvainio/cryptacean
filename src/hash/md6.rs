use crate::hash::{Input, Output};

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

const S_PRIM: u64 = 0x0123456789abcdef;
const S_STAR: u64 = 0x7311c2812425cfa0;

fn pad(input: &Vec<u8>) -> Vec<u32> {
    let mut words: Vec<u32> = Vec::new();
    words
}

fn compress(input: [u64; 74], r: usize) -> [u64; 16] {
    // Q: 15 word u64 constant
    // input contains:
    // K: 8 word key
    // U: 1 word unique ID
    // V: 1 word control
    // B: 64 word data block

    // U can be seen as the level (1 byte) + position within level (7 bytes)
    // V is [four 0 bits, 12 bits representing r, 8 bits representing L/mode, etc.] p.22

    let c = 16;

    // maybe can precompute all Si, if it is module
}

pub struct MD6Key {
    key: Vec<u8>,   // padded with 0 bytes until length 64 within md6
    key_len: usize, // (key length in bytes, 0..=64)
}

impl MD6Key {
    pub fn new() -> Self {}
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
            key: MD6Key::new(),
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
        let input: Vec<u32> = pad(&input.bytes);
        let mut state: Vec<u32> = vec![INIT_A, INIT_B, INIT_C, INIT_D];
        for block in input.chunks(16) {
            let state_copy: Vec<u32> = state.clone();
            let mut idx: VecDeque<usize> = VecDeque::from([0, 1, 2, 3]);
            for round in 0..64 {
                let transform = match round {
                    0..16 => f_transform,
                    16..32 => g_transform,
                    32..48 => h_transform,
                    _ => i_transform,
                };
                state[idx[0]] = state[idx[1]].wrapping_add(
                    state[idx[0]]
                        .wrapping_add(transform(state[idx[1]], state[idx[2]], state[idx[3]]))
                        .wrapping_add(block[K[round]])
                        .wrapping_add(T[round])
                        .rotate_left(S[round]),
                );
                idx.rotate_right(1);
            }
            for i in 0..4 {
                state[i] = state[i].wrapping_add(state_copy[i]);
            }
        }
        Output::from_u32_le(state)
    }
}

// TODO: Implement general MD6 (byte level version)
// TODO: Implement MD6_160, MD6_224, MD6_256, MD6_384, MD6_512
// TODO: Implement test cases for each major version
// TODO: Implement compression function

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md6_160_works() {
        
    }

    #[test]
    fn md6_224_works() {
        
    }

    #[test]
    fn md6_256_works() {
        
    }

    #[test]
    fn md6_384_works() {
        
    }

    #[test]
    fn md6_512_works() {
        
    }
}
