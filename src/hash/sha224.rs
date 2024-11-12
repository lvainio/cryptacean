use crate::hash::{Digest, Endianness, Message};

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: u32 = 0xc1059ed8;
const H1: u32 = 0x367cd507;
const H2: u32 = 0x3070dd17;
const H3: u32 = 0xf70e5939;
const H4: u32 = 0xffc00b31;
const H5: u32 = 0x68581511;
const H6: u32 = 0x64f98fa7;
const H7: u32 = 0xbefa4fa4;

fn pad(input: &Vec<u8>) -> Vec<u32> {
    let input_length: u64 = input.len() as u64;
    let input_length_in_bits: u64 = input_length * 8;
    let length_be_bytes: [u8; 8] = input_length_in_bits.to_be_bytes();

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
    buffer.extend_from_slice(&length_be_bytes);

    let mut words: Vec<u32> = Vec::new();

    for chunk in buffer.chunks_exact(4) {
        let word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        words.push(word);
    }

    words
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn bsig0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

fn bsig1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

fn ssig0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

fn ssig1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

pub struct SHA224;

impl SHA224 {
    pub fn hash(&self, input: &Message) -> Digest {
        let input: Vec<u32> = pad(&input.buffer);
        let mut h: Vec<u32> = vec![H0, H1, H2, H3, H4, H5, H6, H7];

        for block in input.chunks(16) {
            let mut w: Vec<u32> = block.to_vec();

            for t in 16..64 {
                w.push(
                    ssig1(w[t - 2])
                        .wrapping_add(w[t - 7])
                        .wrapping_add(ssig0(w[t - 15]))
                        .wrapping_add(w[t - 16]),
                );
            }

            let mut a = h.clone();

            for t in 0..64 {
                let t1 = a[7]
                    .wrapping_add(bsig1(a[4]))
                    .wrapping_add(ch(a[4], a[5], a[6]))
                    .wrapping_add(K[t])
                    .wrapping_add(w[t]);
                let t2 = bsig0(a[0]).wrapping_add(maj(a[0], a[1], a[2]));

                a[7] = a[6];
                a[6] = a[5];
                a[5] = a[4];
                a[4] = a[3].wrapping_add(t1);
                a[3] = a[2];
                a[2] = a[1];
                a[1] = a[0];
                a[0] = t1.wrapping_add(t2);
            }
            h[0] = h[0].wrapping_add(a[0]);
            h[1] = h[1].wrapping_add(a[1]);
            h[2] = h[2].wrapping_add(a[2]);
            h[3] = h[3].wrapping_add(a[3]);
            h[4] = h[4].wrapping_add(a[4]);
            h[5] = h[5].wrapping_add(a[5]);
            h[6] = h[6].wrapping_add(a[6]);
            h[7] = h[7].wrapping_add(a[7]);
        }
        h.pop();

        Digest::from_u32(&h, Endianness::Big)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha224_on_rfc6234_suite() {
        let hasher = SHA224;
        let i1 = Message::from_string("abc");
        let i2 = Message::from_string("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let i3 = Message::from_string(&"a".repeat(1_000_000));
        let i4 = Message::from_string(
            &"0123456701234567012345670123456701234567012345670123456701234567".repeat(10),
        );

        assert_eq!(
            hasher.hash(&i1).to_hex(),
            "23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7".to_lowercase()
        );
        assert_eq!(
            hasher.hash(&i2).to_hex(),
            "75388B16512776CC5DBA5DA1FD890150B0C6455CB4F58B1952522525".to_lowercase()
        );
        assert_eq!(
            hasher.hash(&i3).to_hex(),
            "20794655980C91D8BBB4C1EA97618A4BF03F42581948B2EE4EE7AD67".to_lowercase()
        );
        assert_eq!(
            hasher.hash(&i4).to_hex(),
            "567F69F168CD7844E65259CE658FE7AADFA25216E68ECA0EB7AB8262".to_lowercase()
        );
    }
}
