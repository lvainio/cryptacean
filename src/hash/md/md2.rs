use crate::hash::{HashFunction, Input, Output};

const S: [u8; 256] = [
    41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19, 98, 167, 5, 243, 192, 199,
    115, 140, 152, 147, 43, 217, 188, 76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66,
    111, 24, 138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47,
    238, 122, 169, 104, 121, 145, 21, 178, 7, 63, 148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93,
    154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165, 181, 209,
    215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107, 226,
    156, 116, 4, 241, 69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
    96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15, 85, 71, 163, 35, 221, 81,
    175, 58, 195, 92, 249, 206, 186, 197, 234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205,
    244, 65, 129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123, 8, 12, 189, 177, 74,
    120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14,
    102, 88, 208, 228, 166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237, 31, 26,
    219, 153, 141, 51, 159, 17, 131, 20,
];

fn pad(input: &Vec<u8>) -> Vec<u8> {
    let input_length: u64 = input.len() as u64;

    let num_padding_bytes: usize = (16 - (input_length % 16)) as usize;

    let padding_byte: u8 = num_padding_bytes as u8;

    let mut buffer: Vec<u8> = Vec::new();
    buffer.extend_from_slice(input);
    buffer.extend(vec![padding_byte; num_padding_bytes]);

    let mut checksum: [u8; 16] = [0; 16];
    let mut l: u8 = 0;
    for chunk in buffer.chunks(16) {
        for j in 0..16 {
            let c = chunk[j];
            // There is an error in the original pseudocode in rfc1319
            // which is explained here:
            // https://www.rfc-editor.org/errata/rfc1319
            checksum[j] = checksum[j] ^ S[(c ^ l) as usize];
            l = checksum[j];
        }
    }
    buffer.extend_from_slice(&checksum);

    buffer
}

pub struct MD2;

impl HashFunction for MD2 {
    fn hash(&self, input: &Input) -> Output {
        let input: Vec<u8> = pad(&input.bytes);
        let mut x: Vec<u8> = vec![0; 48];

        for i in 0..(input.len() / 16) {
            for j in 0..16 {
                x[16 + j] = input[i * 16 + j];
                x[32 + j] = x[16 + j] ^ x[j];
            }
            let mut t: u8 = 0;
            for j in 0..18 {
                for k in 0..48 {
                    t = x[k] ^ S[t as usize];
                    x[k] = t;
                }
                t = t.wrapping_add(j);
            }
        }
        Output::from_u8(x[0..16].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_works_on_rfc1219_suite() {
        let hasher = MD2;
        let i1 = Input::from_string("");
        let i2 = Input::from_string("a");
        let i3 = Input::from_string("abc");
        let i4 = Input::from_string("message digest");
        let i5 = Input::from_string("abcdefghijklmnopqrstuvwxyz");
        let i6 =
            Input::from_string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
        let i7 = Input::from_string(
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        );
        assert_eq!(hasher.hash(&i1).output, "8350e5a3e24c153df2275c9f80692773");
        assert_eq!(hasher.hash(&i2).output, "32ec01ec4a6dac72c0ab96fb34c0b5d1");
        assert_eq!(hasher.hash(&i3).output, "da853b0d3f88d99b30283a69e6ded6bb");
        assert_eq!(hasher.hash(&i4).output, "ab4f496bfb2a530b219ff33031fe06b0");
        assert_eq!(hasher.hash(&i5).output, "4e8ddff3650292ab5a4108c3aa47940b");
        assert_eq!(hasher.hash(&i6).output, "da33def2a42df13975352846c30338cd");
        assert_eq!(hasher.hash(&i7).output, "d5976f79d83d3a0dc9806c3c66f3efd8");
    }

    #[test]
    fn hash_works_on_special_characters() {
        let hasher = MD2;
        let i1 = Input::from_string("こんにちは, 世界! 😊✨");
        let i2 = Input::from_string("안녕하세요, 세상! 🌏🎉");
        assert_eq!(hasher.hash(&i1).output, "4024008b9184e15e14ca56db5d8ba9b7");
        assert_eq!(hasher.hash(&i2).output, "13e9383040d17f2c410aed46676aa873");
    }
}
