use std::collections::VecDeque;

use crate::hash::{Digest, Endianness, Message};

const INIT_A: u32 = 0x67_45_23_01;
const INIT_B: u32 = 0xEF_CD_AB_89;
const INIT_C: u32 = 0x98_BA_DC_FE;
const INIT_D: u32 = 0x10_32_54_76;

const K: [usize; 64] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8,
    13, 2, 7, 12, 5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2, 0, 7, 14, 5, 12, 3, 10, 1,
    8, 15, 6, 13, 4, 11, 2, 9,
];

const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const T: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
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
    (x & z) | (y & !z)
}

fn h_transform(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn i_transform(x: u32, y: u32, z: u32) -> u32 {
    y ^ (x | !z)
}

pub struct MD5;

impl MD5 {
    pub fn hash(&self, input: &Message) -> Digest {
        let input: Vec<u32> = pad(&input.buffer);
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
        Digest::from_u32(&state, Endianness::Little)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_on_rfc1321_suite() {
        let hasher = MD5;
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
            "d41d8cd98f00b204e9800998ecf8427e"
        );
        assert_eq!(
            hasher.hash(&i2).to_hex(),
            "0cc175b9c0f1b6a831c399e269772661"
        );
        assert_eq!(
            hasher.hash(&i3).to_hex(),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            hasher.hash(&i4).to_hex(),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
        assert_eq!(
            hasher.hash(&i5).to_hex(),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
        assert_eq!(
            hasher.hash(&i6).to_hex(),
            "d174ab98d277d9f5a5611c2c9f419d9f"
        );
        assert_eq!(
            hasher.hash(&i7).to_hex(),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }
}
