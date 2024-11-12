use itertools::iproduct;

use crate::hash::{Digest, Endianness, Message};

const RHO_TABLE: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

const RC_TABLE: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/*
Pads the input data according to the SHA-3 and Keccak specification.

The SHA-3 specification states that a "01" bit string is to be added
to the input bit string before applying the keccak sponge function.

The Keccak padding function then appends a '1' bit, zero or more '0' bits,
and then a '1' bit. The final length of the input message should be
congruent to the rate. The two '1' bits are always added.
*/
fn pad(input: &Message, rate: usize) -> Vec<u64> {
    let input_length: usize = input.buffer.len();
    let mut buffer = input.buffer.clone();
    if input_length % rate == rate - 1 {
        buffer.push(0x86); // 1000 0110
    } else {
        let num_zero_bytes = rate - (input_length % rate) - 2;
        buffer.push(0x06); // 0000 0110
        buffer.resize(buffer.len() + num_zero_bytes, 0x00); // 0000 0000
        buffer.push(0x80); // 1000 0000
    }
    let mut words: Vec<u64> = Vec::new();
    for c in buffer.chunks_exact(8) {
        let word = u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
        words.push(word);
    }
    words
}

fn theta(state: &[[u64; 5]; 5]) -> [[u64; 5]; 5] {
    let mut c = [0u64; 5];
    for x in 0..5 {
        c[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4];
    }
    let mut d = [0u64; 5];
    for x in 0..5 {
        d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
    }
    let mut new_state = [[0u64; 5]; 5];
    for (x, y) in iproduct!(0..5, 0..5) {
        new_state[x][y] = state[x][y] ^ d[x];
    }
    new_state
}

fn rho(state: &mut [[u64; 5]; 5]) {
    for (x, y) in iproduct!(0..5, 0..5) {
        state[x][y] = state[x][y].rotate_left(RHO_TABLE[x][y]);
    }
}

fn pi(state: &[[u64; 5]; 5]) -> [[u64; 5]; 5] {
    let mut new_state = [[0u64; 5]; 5];
    for (x, y) in iproduct!(0..5, 0..5) {
        new_state[x][y] = state[(x + 3 * y) % 5][x];
    }
    new_state
}

fn chi(state: &[[u64; 5]; 5]) -> [[u64; 5]; 5] {
    let mut new_state = [[0u64; 5]; 5];
    for (x, y) in iproduct!(0..5, 0..5) {
        new_state[x][y] = state[x][y] ^ (!state[(x + 1) % 5][y] & state[(x + 2) % 5][y]);
    }
    new_state
}

fn iota(state: &mut [[u64; 5]; 5], rnd: usize) {
    state[0][0] ^= RC_TABLE[rnd];
}

fn absorb(input: &Vec<u64>, rate: usize) -> [[u64; 5]; 5] {
    let mut state = [[0u64; 5]; 5];
    for block in input.chunks(rate / 8) {
        for i in 0..(rate / 8) {
            let x = i % 5;
            let y = i / 5;
            state[x][y] ^= block[i];
        }
        for rnd in 0..24 {
            state = theta(&state);
            rho(&mut state);
            state = pi(&state);
            state = chi(&state);
            iota(&mut state, rnd);
        }
    }
    state
}

pub struct SHA3_224 {
    rate: usize,
}

impl SHA3_224 {
    pub fn new() -> Self {
        Self { rate: 144 }
    }

    pub fn hash(&self, input: &Message) -> Digest {
        let padded_input: Vec<u64> = pad(input, self.rate);
        let state = absorb(&padded_input, self.rate);

        let digest = vec![state[0][0], state[1][0], state[2][0], state[3][0]];
        let start_idx = 0;
        let end_idx = (digest.len() * 8) - 4;
        Digest::from_u64_range(&digest, Endianness::Little, start_idx..end_idx).unwrap()
    }
}

pub struct SHA3_256 {
    rate: usize,
}

impl SHA3_256 {
    pub fn new() -> Self {
        Self { rate: 136 }
    }

    pub fn hash(&self, input: &Message) -> Digest {
        let padded_input: Vec<u64> = pad(input, self.rate);
        let state = absorb(&padded_input, self.rate);
        Digest::from_u64(
            &vec![state[0][0], state[1][0], state[2][0], state[3][0]],
            Endianness::Little,
        )
    }
}

pub struct SHA3_384 {
    rate: usize,
}

impl SHA3_384 {
    pub fn new() -> Self {
        Self { rate: 104 }
    }

    pub fn hash(&self, input: &Message) -> Digest {
        let padded_input: Vec<u64> = pad(input, self.rate);
        let state = absorb(&padded_input, self.rate);
        Digest::from_u64(
            &vec![
                state[0][0],
                state[1][0],
                state[2][0],
                state[3][0],
                state[4][0],
                state[0][1],
            ],
            Endianness::Little,
        )
    }
}

pub struct SHA3_512 {
    rate: usize,
}

impl SHA3_512 {
    pub fn new() -> Self {
        Self { rate: 72 }
    }

    pub fn hash(&self, input: &Message) -> Digest {
        let padded_input: Vec<u64> = pad(input, self.rate);
        let state = absorb(&padded_input, self.rate);
        Digest::from_u64(
            &vec![
                state[0][0],
                state[1][0],
                state[2][0],
                state[3][0],
                state[4][0],
                state[0][1],
                state[1][1],
                state[2][1],
            ],
            Endianness::Little,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_224() {
        let sha3_224 = SHA3_224::new();
        let i1 = Message::from_string("abc");
        let i2 = Message::from_string("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");

        assert_eq!(
            sha3_224.hash(&i1).to_hex(),
            "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
        );
        assert_eq!(
            sha3_224.hash(&i2).to_hex(),
            "543e6868e1666c1a643630df77367ae5a62a85070a51c14cbf665cbc"
        );
    }

    #[test]
    fn test_sha3_256() {
        let sha3_256 = SHA3_256::new();
        let i1 = Message::from_string("abc");
        let i2 = Message::from_string("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");

        assert_eq!(
            sha3_256.hash(&i1).to_hex(),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        assert_eq!(
            sha3_256.hash(&i2).to_hex(),
            "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18"
        );
    }

    #[test]
    fn test_sha3_384() {
        let sha3_384 = SHA3_384::new();
        let i1 = Message::from_string("abc");
        let i2 = Message::from_string("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");

        assert_eq!(
            sha3_384.hash(&i1).to_hex(),
            "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"
        );
        assert_eq!(
            sha3_384.hash(&i2).to_hex(),
            "79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179aa7fc7"
        );
    }

    #[test]
    fn test_sha3_512() {
        let sha3_512 = SHA3_512::new();
        let i1 = Message::from_string("abc");
        let i2 = Message::from_string("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");

        assert_eq!(
            sha3_512.hash(&i1).to_hex(),
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        );
        assert_eq!(
            sha3_512.hash(&i2).to_hex(),
            "afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185"
        );
    }
}
