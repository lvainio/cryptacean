use std::{error::Error, fmt, io::Write};

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
pub enum MD6Error {
    KeyLenOutOfBounds,
}

impl fmt::Display for MD6Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MD6Error::KeyLenOutOfBounds => write!(
                f,
                "The provided key is too long for MD6. 0 <= key_len <= 64 bytes."
            ),
        }
    }
}

impl std::error::Error for MD6Error {}

#[derive(Clone)]
pub struct MD6Key {
    key: Vec<u64>,
    key_len: usize,
}

impl MD6Key {
    pub fn new(key: &Vec<u8>) -> Result<Self, MD6Error> {
        const MAX_KEY_LEN: usize = 64;
        let key_len: usize = key.len();
        if key_len > MAX_KEY_LEN {
            return Err(MD6Error::KeyLenOutOfBounds);
        }
        let mut key = key.clone();
        key.resize(64, 0);
        let key: Vec<u64> = key
            .chunks_exact(8)
            .map(|chunk| u64::from_be_bytes(chunk.try_into().unwrap()))
            .collect();
        Ok(Self { key, key_len })
    }
}

fn build_v(r: usize, mode: usize, z: u64, p: usize, key_len: usize, d: usize) -> u64 {
    (r as u64) << 48
        | (mode as u64) << 40
        | z << 36
        | (p as u64) << 20
        | (key_len as u64) << 12
        | d as u64
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

fn seq(prev_message: Vec<u8>, d: usize, key: MD6Key, mode: usize, r: usize, level: u64) -> Vec<u8> {
    let prev_m = prev_message.len() * 8;
    let zero_bytes_to_add = 384 - (prev_message.len() % 384);
    let mut prev_message = prev_message.clone();
    prev_message.resize(prev_message.len() + zero_bytes_to_add, 0u8);

    let prev_message: Vec<u64> = to_u64_vec_be(prev_message);

    let mut new_message: Vec<u64> = Vec::new();

    vec![]
}

// REQUIREMENTS:
// d: 1..=512
// L: 0..=64

pub struct MD6 {
    d: usize,     // (output length in bits, 1..=512)
    key: MD6Key, // Optional (not sure what happens when null yet so lets keep it like this for now TODO:)
    mode: u64, // 0..=64 Optional but has a default value so should NOT be an Option TODO Switch to usize?
    r: usize,  // (number of rounds)
    level: usize, // tree level
    rc: Vec<u64>,
}

impl MD6 {
    pub fn new(d: usize) -> Self {
        let r: usize = 40 + (d / 4);
        let mut rc: Vec<u64> = vec![S_PRIM_0];
        for i in 1..r {
            rc.push(rc[i - 1].rotate_left(1) ^ (rc[i - 1] & S_STAR));
        }
        Self {
            d,
            key: MD6Key::new(&vec![]).unwrap(),
            mode: 64,
            r,
            level: 0,
            rc,
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
        let mut rc: Vec<u64> = vec![S_PRIM_0];
        for i in 1..r {
            rc.push(rc[i - 1].rotate_left(1) ^ (rc[i - 1] & S_STAR));
        }
        self.r = r;
        self.rc = rc;
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

        level += 1;
        let mut new_message: Vec<u8> = self.par(input.clone(), level);

        while new_message.len() * 8 != c * WORD_LENGTH {
            level += 1;
            new_message = self.par(new_message.clone(), level);
        }

        let d_bytes = d / 8;
        Output::from_u8(new_message[new_message.len() - d_bytes..].to_vec())
    }

    fn compress(&self, a_vec: &mut Vec<u64>) {
        const N: usize = 89;
        const C: usize = 16;
        let t: usize = self.r * C;

        for i in N..(t + N) {
            let mut x = self.rc[(i - N) / 16] ^ a_vec[i - N] ^ a_vec[i - T0];
            x ^= (a_vec[i - T1] & a_vec[i - T2]) ^ (a_vec[i - T3] & a_vec[i - T4]);
            x ^= x >> RIGHT_SHIFTS[(i - N) % C];
            a_vec.push(x ^ (x << LEFT_SHIFTS[(i - N) % C]));
        }
    }

    

    fn par(&self, prev_message: Vec<u8>, level: u64) -> Vec<u8> {
        let prev_m = prev_message.len() * 8;

        // TODO: idea of just doing a pad in beginning so i can send u64s to this function only!!!

        let mut zero_bytes_to_add = 512 - (prev_message.len() % 512);
        if zero_bytes_to_add % 512 == 0 && prev_m > 0 {
            zero_bytes_to_add = 0;
        }

        let mut prev_message = prev_message.clone();
        prev_message.resize(prev_message.len() + zero_bytes_to_add, 0u8);

        let prev_m = prev_message.len() * 8;

        let prev_message: Vec<u64> = to_u64_vec_be(prev_message);

        let mut new_message: Vec<u64> = Vec::new(); // allocate correct size directly no

        let b = 64;
        let j = (1).max(prev_m / (b * WORD_LENGTH));

        for i in 0..j {
            // STEP 1
            let mut p = 0;
            if i == j - 1 {
                p = zero_bytes_to_add * 8;
            }

            let z: u64 = if j == 1 { 1 } else { 0 };
            let v: u64 = build_v(self.r, self.mode as usize, z, p, self.key.key_len, self.d);
            let u: u64 = level * 2u64.pow(56) + i as u64;

            let mut input: Vec<u64> = Vec::with_capacity(89);
            input.extend_from_slice(&Q);
            input.extend_from_slice(&self.key.key.as_slice());
            input.push(u);
            input.push(v);
            input.extend_from_slice(&prev_message[i * 64..((i + 1) * 64)]);

            self.compress(&mut input);

            let chunk: &[u64] = &input[input.len() - 16..];

            new_message.extend_from_slice(&chunk);
        }

        let new_message = to_u8_vec_be(new_message);

        new_message
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_constructor() {
        let key1 = MD6Key::new(&vec![]).unwrap();
        let key2 = MD6Key::new(&vec![0]).unwrap();
        let key3 = MD6Key::new(&vec![0xff, 0x00, 0xff]).unwrap();
        let key4 = MD6Key::new(&vec![0xff; 64]).unwrap();

        assert_eq!(key1.key, vec![0; 8]);
        assert_eq!(key2.key, vec![0; 8]);
        assert_eq!(key3.key, vec![0xff00_ff00_0000_0000, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(key4.key, vec![0xffff_ffff_ffff_ffff; 8]);

        let result = MD6Key::new(&vec![0; 65]);
        assert!(matches!(result, Err(MD6Error::KeyLenOutOfBounds)));
    }

    const NUM_INPUTS: usize = 10;
    const INPUTS: [(&str, usize); NUM_INPUTS] = [
        ("", 1),
        ("abc", 1),
        ("a", 512),
        ("a", 1_000_000),
        ("hello", 100),
        ("rust", 256),
        ("test", 500),
        ("a", 100),
        ("longteststring", 20),
        ("anotherstring", 1024),
    ];

    #[test]
    fn test_md6_160() {
        const EXPECTED: [&str; NUM_INPUTS] = [
            "f325ee93c54cfaacd7b9007e1cf8904680993b18",
            "b5c2d6a7ce6be0c18c9a38b17a0db705c81ab6b5",
            "0082b7cb6950bdfd20efb973e10e3554bf0f8ea2",
            "c4c60228667e2e413f7136925d7a316652f43e81",
            "a55e464fd95edeb3f8f29cbcacc9df3e49157243",
            "ca9d930924fec9f4989523eb41cf1130621398bb",
            "fe4abccaa74b8189724af1836c7b27500c8039df",
            "2a88663bf35a0f159e534af11f771df262438e43",
            "d9abbea71dcd76f291d3d84c1bc3436f6fe2cff2",
            "d3d3baf7ad8070a1dfd9cfa56f11edfd3c079fb1",
        ];
        let md6_160 = MD6_160::new();
        for i in 0..NUM_INPUTS {
            let (input_string, repeats) = INPUTS[i];
            let input = Input::from_string(&input_string.repeat(repeats));
            assert_eq!(md6_160.hash(&input).output, EXPECTED[i]);
        }
    }

    #[test]
    fn test_md6_224() {
        const EXPECTED: [&str; NUM_INPUTS] = [
            "d2091aa2ad17f38c51ade2697f24cafc3894c617c77ffe10fdc7abcb",
            "510c30e4202a5cdd8a4f2ae9beebb6f5988128897937615d52e6d228",
            "17e01a3c84844f9cc0771d1130d15a963f0d596019eb5b0068c8cee6",
            "5571b826edd9992af4379d92061f8fc16466641433fb49db0c9df7f3",
            "e98ebd5a0864be4e04718c67b820075301ed412b3aabd51f34c4e969",
            "e532f265e2c7fdb0582a8830627eb7122b34d42541ee34c38a343706",
            "dc493ce1142ac82cb5f2f1795d219f1447af22e5de66787fc0676379",
            "51f2d61054834736812bc30d025513b168e3c16759383fc31df47aef",
            "f7585dec4be05cdbbf96598be5d8490513735691314d05e3c934989e",
            "b670f93a34c67ddd3020249db80d18353245c67cdd67f4917f2d82eb",
        ];
        let md6_224 = MD6_224::new();
        for i in 0..NUM_INPUTS {
            let (input_string, repeats) = INPUTS[i];
            let input = Input::from_string(&input_string.repeat(repeats));
            assert_eq!(md6_224.hash(&input).output, EXPECTED[i]);
        }
    }

    #[test]
    fn test_md6_256() {
        const EXPECTED: [&str; NUM_INPUTS] = [
            "bca38b24a804aa37d821d31af00f5598230122c5bbfc4c4ad5ed40e4258f04ca",
            "230637d4e6845cf0d092b558e87625f03881dd53a7439da34cf3b94ed0d8b2c5",
            "404755fc05393be32dadac0a43ca2bf96e139f620af2186ec5d1d4acb53917d1",
            "2616ad6631304206654fd0e3eff756565714b7f442e49685192cae66e021deb0",
            "bbd72e737bb097896f4f9b5a53dea69b1c57237c0051e9693556d3d7f197f32f",
            "a572d547fde5cf6c97db8bf5e35eb45441908f9580dcdd16dbcf0ec2f5a291fc",
            "97d5e3fa526a95e28e58b6f0a9a3cf1e77dca2bf112b0959c736213da7c1c02d",
            "424081e3e3e963111d75624e72a2bff8efbb44bf97e9f80c0a933eaeb4b5adb7",
            "a7b1779ceb4c5f0d262bac83e124f9c3f0d0a31d716d1ca60575dc128c3e37a7",
            "393b519758348347c02e1070615c1cd61efc97e5157f3a9127806126ea7c0dc9",
        ];
        let md6_256 = MD6_256::new();
        for i in 0..NUM_INPUTS {
            let (input_string, repeats) = INPUTS[i];
            let input = Input::from_string(&input_string.repeat(repeats));
            assert_eq!(md6_256.hash(&input).output, EXPECTED[i]);
        }
    }

    #[test]
    fn test_md6_384() {
        const EXPECTED: [&str; NUM_INPUTS] = [
            "b0bafffceebe856c1eff7e1ba2f539693f828b532ebf60ae9c16cbc3499020401b942ac25b310b2227b2954ccacc2f1f", 
            "e2c6d31dd8872cbd5a1207481cdac581054d13a4d4fe6854331cd8cf3e7cbafbaddd6e2517972b8ff57cdc4806d09190",
            "012e6c72d92cdfed662aefc2dd55949607ecdebe43d7b4dd62102814e629f05687f3c92e1ba0d96d6b733db718984a1d",
            "6368d6cb5587e7b6ebd50e00c4a608b71956c057c114d2219b659a5638d01dc4f5915cfa1f0a42b897dbd0b18330a276", 
            "ca703c5d74e3f327160a4a01ec53dd8e9aae82c0d4348e4d9fe44e2503b30c8d462b2339c93617a3334b6f2db4b41a00",
            "10dba507fa6a0d1c3ba6d69376b8145dfa63daada4289138bbbdc534629cc2dc08548dcdc26bcbf21d9ac9c4386c5c98",
            "88409a0026b680347367ce4f1c43b3d51ada8f344213667d67e09acf63d53442a4a227cc62ce5289a8a47d933bb549dd",
            "ae2ac987984e3e0ef542997e6ce7ca43151b6d3c6703d1034466c9290f0628dea7cc247ea7ce66d7e48bbce423292df3",
            "ba442c277845f2b7883f672f11a29d4b9ee037aaaa3da04e91523804e4f7397d12324301b697f721e1509c4a8cce2ae6",
            "771c37125219cc43fd1ec99528e83ce20a8f774f6a8b4b1d10ae878cc7dc6da0c0970650a78bde3eec151c65a022e8cc",
        ];
        let md6_384 = MD6_384::new();
        for i in 0..NUM_INPUTS {
            let (input_string, repeats) = INPUTS[i];
            let input = Input::from_string(&input_string.repeat(repeats));
            assert_eq!(md6_384.hash(&input).output, EXPECTED[i]);
        }
    }

    #[test]
    fn test_md6_512() {
        const EXPECTED: [&str; NUM_INPUTS] = [
            "6b7f33821a2c060ecdd81aefddea2fd3c4720270e18654f4cb08ece49ccb469f8beeee7c831206bd577f9f2630d9177979203a9489e47e04df4e6deaa0f8e0c0", 
            "00918245271e377a7ffb202b90f3bda5477d8feab12d8a3a8994ebc55fe6e74ca8341520032eeea3fdef892f2882378f636212af4b2683ccf80bf025b7d9b457",
            "6acc45ceb67c106eff5a2a98853bc885196341d66a5c81916e27df955ad234a9fb2d9ae2e7dcf92a4f1e62875ee44ef58e87b2be9a7fd43ef9b1ae6969e6a86b",
            "3061f95972662f557f6eb0f4d1dad8908f725e95576beaf2899382fb86d7815871a0671f17e0de58eee7538f6596c1fb9c4dd3fccee64f9fd1bc0bdcf537ecf9", 
            "59a27491603bf61c3ed269772828af15eb5914a495a7c7bb30ad4b48d43d861173f18f283840a272c68c75e26f6df0f834a8c49b701743c5d7c5317a851ce7ba",
            "8438f46327f35296dad90188c857dac15650e0de9f520b52d68cc3f74da1686878a8331488cca1e270c07334bcbc10ee9207192b4fec5479618fd471855c8b77",
            "e3b54b8e9cc8b1dfd3776d18b33eafc2f30d3eb1286de52a6587711ef7eadde26c0cebb2989a40cd8bb7ce98c7a95351f0c765b1ec1fb21559dd960a11f8256f",
            "7c71a2eead8f46c13ad552bedea24c7ebbfe5280908c5807f747d5f1c46e2e65f405e71c9c07b2286059cb60a2086d9872a2f5612c08240dc9b9e6ee78a883f8",
            "5197f2b474e660d507eab66a0cf934e009726511c5416d6077c02d64eff8ac714c8f179d3be0b02ee2db37707dba3f1dd0d38aaa00002cb97c7ae9198f33d19e",
            "0f85708db81da5cc9f9073a60e41d4da731d572dde41f688861729ec1cf989b406167d894e99bb5b735689bbbe046fcd0eb9dea2d5f3ef4201e487e0b7cc77f9",
        ];
        let md6_512 = MD6_512::new();
        for i in 0..NUM_INPUTS {
            let (input_string, repeats) = INPUTS[i];
            let input = Input::from_string(&input_string.repeat(repeats));
            assert_eq!(md6_512.hash(&input).output, EXPECTED[i]);
        }
    }
}
