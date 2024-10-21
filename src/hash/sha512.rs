use super::{HashFunction, Input, Output};

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

const H0: u64 = 0x6a09e667f3bcc908;
const H1: u64 = 0xbb67ae8584caa73b;
const H2: u64 = 0x3c6ef372fe94f82b;
const H3: u64 = 0xa54ff53a5f1d36f1;
const H4: u64 = 0x510e527fade682d1;
const H5: u64 = 0x9b05688c2b3e6c1f;
const H6: u64 = 0x1f83d9abfb41bd6b;
const H7: u64 = 0x5be0cd19137e2179;

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

pub struct SHA512;

impl HashFunction for SHA512 {
    fn hash(&self, input: &Input) -> Output {
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
        Output::from_u64_be(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_works_on_rfc6234_suite() {
        let hasher = SHA512;
        let i1 = Input::from_string("abc");
        let i2 = Input::from_string("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        let i3 = Input::from_string(&"a".repeat(1_000_000));
        let i4 = Input::from_string(
            &"0123456701234567012345670123456701234567012345670123456701234567".repeat(10),
        );

        assert_eq!(
            hasher.hash(&i1).output,
            "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F".to_lowercase()
        );
        assert_eq!(
            hasher.hash(&i2).output,
            "8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909".to_lowercase()
        );
        assert_eq!(
            hasher.hash(&i3).output,
            "E718483D0CE769644E2E42C7BC15B4638E1F98B13B2044285632A803AFA973EBDE0FF244877EA60A4CB0432CE577C31BEB009C5C2C49AA2E4EADB217AD8CC09B".to_lowercase()
        );
        assert_eq!(
            hasher.hash(&i4).output,
            "89D05BA632C699C31231DED4FFC127D5A894DAD412C0E024DB872D1ABD2BA8141A0F85072A9BE1E2AA04CF33C765CB510813A39CD5A84C4ACAA64D3F3FB7BAE9".to_lowercase()
        );
    }

    #[test]
    fn hash_works_on_special_characters() {
        let hasher = SHA512;
        let i1 = Input::from_string("こんにちは, 世界! 😊✨");
        let i2 = Input::from_string("안녕하세요, 세상! 🌏🎉");
        assert_eq!(
            hasher.hash(&i1).output,
            "5d314541efc88266b27e8c0431a8f87e9f3a931cf5fb7c2bb3c7f364b49b0849fb0212cb379897cfb2e23f971864dcacb83ade90071ca5caced84c499936cc07"
        );
        assert_eq!(
            hasher.hash(&i2).output,
            "1ef90b0093a91c9d8ea3fc7a8d70a263d7c931c28a699a07bb58439636213823e5c6df133a20a84d754e641d920c021def5347e74482bb3f5651e9ae645008c5"
        );
    }
}
