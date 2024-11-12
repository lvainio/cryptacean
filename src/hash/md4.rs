use std::collections::VecDeque;

use crate::hash::{Digest, Endianness, Message};

const INIT_A: u32 = 0x67_45_23_01;
const INIT_B: u32 = 0xEF_CD_AB_89;
const INIT_C: u32 = 0x98_BA_DC_FE;
const INIT_D: u32 = 0x10_32_54_76;

const K: [usize; 48] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14,
    3, 7, 11, 15, 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15,
];

const S: [u32; 48] = [
    3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19, 3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13,
    3, 5, 9, 13, 3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15,
];

fn pad(input: &Vec<u8>) -> Vec<u32> {
    let input_length: u64 = input.len() as u64;
    let input_length_in_bits: u64 = input_length * 8;
    let length_le_bytes: [u8; 8] = input_length_in_bits.to_le_bytes();

    let input_length_mod_64: u64 = input_length % 64;
    let padding_length: u64 = match input_length_mod_64 {
        56 => 64,
        _ => (56 + 64 - input_length_mod_64) % 64,
    };

    let total_length = (input_length + padding_length + 8) as usize;
    let mut buffer: Vec<u8> = Vec::with_capacity(total_length);

    buffer.extend_from_slice(input);
    buffer.push(0x80);
    buffer.resize((input_length + padding_length) as usize, 0x00);
    buffer.extend_from_slice(&length_le_bytes);

    let mut words: Vec<u32> = Vec::new();

    for chunk in buffer.chunks_exact(4) {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        words.push(word);
    }

    words
}

fn f_transform(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

fn g_transform(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

fn h_transform(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

pub struct MD4;

impl MD4 {
    pub fn hash(&self, input: &Message) -> Digest {
        let input: Vec<u32> = pad(&input.buffer);
        let mut state: Vec<u32> = vec![INIT_A, INIT_B, INIT_C, INIT_D];
        for block in input.chunks(16) {
            let state_copy: Vec<u32> = state.clone();
            let mut idx: VecDeque<usize> = VecDeque::from([0, 1, 2, 3]);
            for round in 0..48 {
                let (transform, c): (fn(u32, u32, u32) -> u32, u32) = match round {
                    0..16 => (f_transform, 0),
                    16..32 => (g_transform, 0x5A827999),
                    _ => (h_transform, 0x6ED9EBA1),
                };
                state[idx[0]] = state[idx[0]]
                    .wrapping_add(transform(state[idx[1]], state[idx[2]], state[idx[3]]))
                    .wrapping_add(block[K[round]])
                    .wrapping_add(c)
                    .rotate_left(S[round]);

                idx.rotate_right(1);
            }
            for i in 0..4 {
                state[i] = state[i].wrapping_add(state_copy[i]);
            }
        }
        Digest::from_u32(&state, Endianness::Little)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md4_on_rfc1320_suite() {
        let hasher = MD4;
        let i1 = Message::from_string("");
        let i2 = Message::from_string("a");
        let i3 = Message::from_string("abc");
        let i4 = Message::from_string("message digest");
        let i5 = Message::from_string("abcdefghijklmnopqrstuvwxyz");
        let i6 =
            Message::from_string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
        let i7 = Message::from_string(
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        );
        assert_eq!(
            hasher.hash(&i1).to_hex(),
            "31d6cfe0d16ae931b73c59d7e0c089c0"
        );
        assert_eq!(
            hasher.hash(&i2).to_hex(),
            "bde52cb31de33e46245e05fbdbd6fb24"
        );
        assert_eq!(
            hasher.hash(&i3).to_hex(),
            "a448017aaf21d8525fc10ae87aa6729d"
        );
        assert_eq!(
            hasher.hash(&i4).to_hex(),
            "d9130a8164549fe818874806e1c7014b"
        );
        assert_eq!(
            hasher.hash(&i5).to_hex(),
            "d79e1c308aa5bbcdeea8ed63df412da9"
        );
        assert_eq!(
            hasher.hash(&i6).to_hex(),
            "043f8582f241db351ce627e153e7f0e4"
        );
        assert_eq!(
            hasher.hash(&i7).to_hex(),
            "e33b4ddc9c38f2199c3e7b164fcc0536"
        );
    }
}
