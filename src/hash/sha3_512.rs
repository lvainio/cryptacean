use itertools::iproduct;

use crate::hash::{Input, Output};

const RHO_TABLE: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 78],
];

const PI_TABLE: [[(usize, usize); 5]; 5] = [
    [(0, 0), (1, 3), (2, 1), (3, 4), (4, 2)],
    [(0, 2), (1, 0), (2, 3), (3, 1), (4, 4)],
    [(0, 4), (1, 2), (2, 0), (3, 3), (4, 1)],
    [(0, 1), (1, 4), (2, 2), (3, 0), (4, 3)],
    [(0, 3), (1, 1), (2, 4), (3, 2), (4, 0)],
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

fn pad(input: &mut Vec<u8>) -> Vec<u64> {
    let input_length: usize = input.len();

    if input_length % 72 == 71 {
        input.push(0x86); // 1000 0110
    } else {
        let num_zero_bytes = 72 - (input_length % 72) - 2;
        input.push(0x06); // 0000 0110
        input.resize(input.len() + num_zero_bytes, 0x00); // 0000 0000
        input.push(0x80); // 1000 0000
    }

    let mut words: Vec<u64> = Vec::new();
    for c in input.chunks_exact(8) {
        let word = u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
        words.push(word);
    }

    words
}

struct State {
    array: [[u64; 5]; 5],
}

impl State {
    fn new() -> Self {
        State {
            array: [[0u64; 5]; 5],
        }
    }

    fn get_lane(&self, x: usize, y: usize) -> u64 {
        self.array[x][y]
    }

    fn set_lane(&mut self, x: usize, y: usize, val: u64) {
        self.array[x][y] = val;
    }
}

pub struct SHA3_512;

impl SHA3_512 {
    fn theta(state: State) -> State {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state.get_lane(x, 0)
                ^ state.get_lane(x, 1)
                ^ state.get_lane(x, 2)
                ^ state.get_lane(x, 3)
                ^ state.get_lane(x, 4);
        }

        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }

        let mut new_state = State::new();
        for (x, y) in iproduct!(0..5, 0..5) {
            new_state.set_lane(x, y, state.get_lane(x, y) ^ d[x]);
        }

        new_state
    }

    fn rho(state: &mut State) {
        for (x, y) in iproduct!(0..5, 0..5) {
            state.array[x][y] = state.array[x][y].rotate_left(RHO_TABLE[x][y]);
        }
    }

    fn pi(state: State) -> State {
        let mut new_state = State::new();
        for (x, y) in iproduct!(0..5, 0..5) {
            let (to_x, to_y) = PI_TABLE[x][y];
            new_state.array[to_x][to_y] = state.array[x][y];
        }
        new_state
    }

    fn chi(state: State) -> State {
        let mut new_state = State::new();
        for (x, y) in iproduct!(0..5, 0..5) {
            new_state.array[x][y] =
                state.array[x][y] ^ (!state.array[(x + 1) % 5][y] & state.array[(x + 2) % 5][y]);
        }
        new_state
    }

    fn iota(state: &mut State, rnd: usize) {
        state.array[0][0] ^= RC_TABLE[rnd];
    }
}

impl SHA3_512 {
    pub fn hash(&self, input: &Input) -> Output {
        let padded_input: Vec<u64> = pad(&mut input.bytes.clone());
        let mut state = State::new();

        for block in padded_input.chunks(9) {
            state.array[0][0] ^= block[0];
            state.array[1][0] ^= block[1];
            state.array[2][0] ^= block[2];
            state.array[3][0] ^= block[3];
            state.array[4][0] ^= block[4];

            state.array[0][1] ^= block[5];
            state.array[1][1] ^= block[6];
            state.array[2][1] ^= block[7];
            state.array[3][1] ^= block[8];

            for rnd in 0..24 {
                state = Self::theta(state);
                Self::rho(&mut state);
                state = Self::pi(state);
                state = Self::chi(state);
                Self::iota(&mut state, rnd);
            }
        }

        Output::from_u64_le(vec![
            state.array[0][0],
            state.array[1][0],
            state.array[2][0],
            state.array[3][0],
            state.array[4][0],
            state.array[0][1],
            state.array[1][1],
            state.array[2][1],
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_works() {
        let hasher = SHA3_512;
        let i1 = Input::from_string("abc");
        let i2 = Input::from_string("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");

        assert_eq!(
            hasher.hash(&i1).output,
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        );
        assert_eq!(
            hasher.hash(&i2).output,
            "afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185"
        );
    }

    #[test]
    fn hash_works_on_special_characters() {
        let hasher = SHA3_512;
        let i1 = Input::from_string("こんにちは, 世界! 😊✨");
        let i2 = Input::from_string("안녕하세요, 세상! 🌏🎉");
        assert_eq!(
            hasher.hash(&i1).output,
            "a25730dee429c06b97fd9bb8275261868f50f053548d70567dc9ef2298df1d9f439e7d69f2929a6e3a3f5ad4fe2ed8c5f9bdd17b35215c74b298d909bfb708ca"
        );
        assert_eq!(
            hasher.hash(&i2).output,
            "1f5dcef717b82170fa5f2075994a41fd95c7481454620f8802d7d86f92b7075b7e7ac3a2515907bf7b58f93366fe725505dcfd5a99314f1a344423c8d8ffa9fb"
        );
    }
}
