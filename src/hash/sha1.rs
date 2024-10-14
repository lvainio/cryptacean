use super::{HashFunction, Input, Output};

const H0: u32 = 0x67452301;
const H1: u32 = 0xEFCDAB89;
const H2: u32 = 0x98BADCFE;
const H3: u32 = 0x10325476;
const H4: u32 = 0xC3D2E1F0;

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

fn transform(t: u32, b: u32, c: u32, d: u32) -> u32 {
    match t {
        0..=19 => (b & c) | (!b & d),
        20..=39 => b ^ c ^ d,
        40..=59 => (b & c) | (b & d) | (c & d),
        _ => b ^ c ^ d,
    }
}

fn k(t: u32) -> u32 {
    match t {
        0..=19 => 0x5A827999,
        20..=39 => 0x6ED9EBA1,
        40..=59 => 0x8F1BBCDC,
        _ => 0xCA62C1D6,
    }
}

pub struct SHA1;

impl HashFunction for SHA1 {
    fn hash(&self, input: &Input) -> Output {
        let input: Vec<u32> = pad(&input.bytes);
        let mut h: Vec<u32> = vec![H0, H1, H2, H3, H4];

        for block in input.chunks(16) {
            let mut w: Vec<u32> = block.to_vec();

            for t in 16..80 {
                w.push((w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1));
            }

            let mut a = h.clone();

            for t in 0..80 {
                let temp = a[0]
                    .rotate_left(5)
                    .wrapping_add(transform(t, a[1], a[2], a[3]))
                    .wrapping_add(a[4])
                    .wrapping_add(w[t as usize])
                    .wrapping_add(k(t));

                a[4] = a[3];
                a[3] = a[2];
                a[2] = a[1].rotate_left(30);
                a[1] = a[0];
                a[0] = temp;
            }

            h[0] = h[0].wrapping_add(a[0]);
            h[1] = h[1].wrapping_add(a[1]);
            h[2] = h[2].wrapping_add(a[2]);
            h[3] = h[3].wrapping_add(a[3]);
            h[4] = h[4].wrapping_add(a[4]);
        }

        Output::from_u32_be(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_works_on_rfc3174_suite() {
        let hasher = SHA1;
        let i1 = Input::from_string("abc");
        let i2 = Input::from_string("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let i3 = Input::from_string(&"a".repeat(1_000_000));
        let i4 = Input::from_string(
            &"0123456701234567012345670123456701234567012345670123456701234567".repeat(10),
        );

        assert_eq!(
            hasher.hash(&i1).output,
            "A9993E364706816ABA3E25717850C26C9CD0D89D".to_lowercase()
        );
        assert_eq!(
            hasher.hash(&i2).output,
            "84983E441C3BD26EBAAE4AA1F95129E5E54670F1".to_lowercase()
        );
        assert_eq!(
            hasher.hash(&i3).output,
            "34AA973CD4C4DAA4F61EEB2BDBAD27316534016F".to_lowercase()
        );
        assert_eq!(
            hasher.hash(&i4).output,
            "DEA356A2CDDD90C7A7ECEDC5EBB563934F460452".to_lowercase()
        );
    }

    #[test]
    fn hash_works_on_special_characters() {
        let hasher = SHA1;
        let i1 = Input::from_string("こんにちは, 世界! 😊✨");
        let i2 = Input::from_string("안녕하세요, 세상! 🌏🎉");
        assert_eq!(
            hasher.hash(&i1).output,
            "ce98b555c324805e35e57209df43c0be3c3574fb"
        );
        assert_eq!(
            hasher.hash(&i2).output,
            "6b0ee0d3ddbf61b378f1889adf945f8894391325"
        );
    }
}
