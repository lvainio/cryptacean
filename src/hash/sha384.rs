use crate::hash::{Input, Output};

const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

const H0: u64 = 0xcbbb9d5dc1059ed8;
const H1: u64 = 0x629a292a367cd507;
const H2: u64 = 0x9159015a3070dd17;
const H3: u64 = 0x152fecd8f70e5939;
const H4: u64 = 0x67332667ffc00b31;
const H5: u64 = 0x8eb44a8768581511;
const H6: u64 = 0xdb0c2e0d64f98fa7;
const H7: u64 = 0x47b5481dbefa4fa4;

fn pad(input: &Vec<u8>) -> Vec<u64> {
    let input_length: u128 = input.len() as u128;
    let input_length_in_bits: u128 = input_length * 8;
    let length_be_bytes: [u8; 16] = input_length_in_bits.to_be_bytes();

    let input_length_mod_128: u128 = input_length % 128;
    let padding_length: u128 = match input_length_mod_128 {
        112 => 128,
        _ => (112 + 128 - input_length_mod_128) % 128,
    };

    let total_length = (input_length + padding_length + 8) as usize;
    let mut buffer: Vec<u8> = Vec::with_capacity(total_length);

    buffer.extend_from_slice(input);
    buffer.push(0x80);
    buffer.resize((input_length + padding_length) as usize, 0x00);
    buffer.extend_from_slice(&length_be_bytes);

    let mut words: Vec<u64> = Vec::new();

    for c in buffer.chunks_exact(8) {
        let word = u64::from_be_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
        words.push(word);
    }

    words
}

fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn bsig0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

fn bsig1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

fn ssig0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

fn ssig1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

pub struct SHA384;

impl SHA384 {
    pub fn hash(&self, input: &Input) -> Output {
        let input: Vec<u64> = pad(&input.bytes);
        let mut h: Vec<u64> = vec![H0, H1, H2, H3, H4, H5, H6, H7];

        for block in input.chunks(16) {
            let mut w: Vec<u64> = block.to_vec();

            for t in 16..80 {
                w.push(
                    ssig1(w[t - 2])
                        .wrapping_add(w[t - 7])
                        .wrapping_add(ssig0(w[t - 15]))
                        .wrapping_add(w[t - 16]),
                );
            }

            let mut a = h.clone();

            for t in 0..80 {
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
        h.pop();
        Output::from_u64_be(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_works_on_rfc6234_suite() {
        let hasher = SHA384;
        let i1 = Input::from_string("abc");
        let i2 = Input::from_string("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        let i3 = Input::from_string(&"a".repeat(1_000_000));
        let i4 = Input::from_string(
            &"0123456701234567012345670123456701234567012345670123456701234567".repeat(10),
        );

        assert_eq!(
            hasher.hash(&i1).output,
            "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7".to_lowercase()
        );
        assert_eq!(
            hasher.hash(&i2).output,
            "09330C33F71147E83D192FC782CD1B4753111B173B3B05D22FA08086E3B0F712FCC7C71A557E2DB966C3E9FA91746039".to_lowercase()
        );
        assert_eq!(
            hasher.hash(&i3).output,
            "9D0E1809716474CB086E834E310A4A1CED149E9C00F248527972CEC5704C2A5B07B8B3DC38ECC4EBAE97DDD87F3D8985".to_lowercase()
        );
        assert_eq!(
            hasher.hash(&i4).output,
            "2FC64A4F500DDB6828F6A3430B8DD72A368EB7F3A8322A70BC84275B9C0B3AB00D27A5CC3C2D224AA6B61A0D79FB4596".to_lowercase()
        );
    }

    #[test]
    fn hash_works_on_special_characters() {
        let hasher = SHA384;
        let i1 = Input::from_string("こんにちは, 世界! 😊✨");
        let i2 = Input::from_string("안녕하세요, 세상! 🌏🎉");
        assert_eq!(
            hasher.hash(&i1).output,
            "ef302cf00cfec95140f64fee17056a66e2fd8185912c0a65fb6c9f49f9d907cd153d052c2071953f6049cea7bb7d6f21"
        );
        assert_eq!(
            hasher.hash(&i2).output,
            "3b24f81c896b6cd04da1890835673f6119d40d6377b3cd51c2f44c5daf01ae82f53700c0cb5b2b6a79df629cf1bdcae5"
        );
    }
}
