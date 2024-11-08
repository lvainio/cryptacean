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

    if input_length % 104 == 103 {
        input.push(0x86); // 1000 0110
    } else {
        let num_zero_bytes = 104 - (input_length % 104) - 2;
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

pub struct SHA3_384;

impl SHA3_384 {
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

impl SHA3_384 {
    pub fn hash(&self, input: &Input) -> Output {
        let padded_input: Vec<u64> = pad(&mut input.bytes.clone());
        let mut state = State::new();

        for block in padded_input.chunks(13) {
            state.array[0][0] ^= block[0];
            state.array[1][0] ^= block[1];
            state.array[2][0] ^= block[2];
            state.array[3][0] ^= block[3];
            state.array[4][0] ^= block[4];

            state.array[0][1] ^= block[5];
            state.array[1][1] ^= block[6];
            state.array[2][1] ^= block[7];
            state.array[3][1] ^= block[8];
            state.array[4][1] ^= block[9];

            state.array[0][2] ^= block[10];
            state.array[1][2] ^= block[11];
            state.array[2][2] ^= block[12];

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
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_works() {
        let hasher = SHA3_384;
        let i1 = Input::from_string("abc");
        let i2 = Input::from_string("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");

        assert_eq!(
            hasher.hash(&i1).output,
            "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"
        );
        assert_eq!(
            hasher.hash(&i2).output,
            "79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179aa7fc7"
        );
    }

    #[test]
    fn hash_works_on_special_characters() {
        let hasher = SHA3_384;
        let i1 = Input::from_string("こんにちは, 世界! 😊✨");
        let i2 = Input::from_string("안녕하세요, 세상! 🌏🎉");
        assert_eq!(
            hasher.hash(&i1).output,
            "5ccf9582b944306a2148dbae179e86514c0cf1ee52c7d0d526aae964329304cf5c134b8f45f61bfa5cfa2ee0696c6710"
        );
        assert_eq!(
            hasher.hash(&i2).output,
            "c21027c1006737b0d900480a315b1104523d06f9438f57926662d73ab69bb11a892bdc8b792c875b81197a6e18f2cc54"
        );
    }
}
