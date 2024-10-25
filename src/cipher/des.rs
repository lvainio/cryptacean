const PC_1: [usize; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

const PC_2: [usize; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

const key_shifts: [usize; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

struct Subkey {
    left: u64,
    right: u64,
}

impl Subkey {}

pub struct DES {
    subkeys: [Subkey; 16],
}

impl DES {
    fn key_schedule(key: u64) {
        let mut left_key: u64 = 0;
        for (i, v) in PC_1[0..28].iter().enumerate() {
            let key_bit_value = ((key >> (64 - v)) & 1) << (27 - i);
            left_key |= key_bit_value;
        }
        let mut right_key: u64 = 0;
        for (i, v) in PC_1[28..56].iter().enumerate() {
            let key_bit_value = ((key >> (64 - v)) & 1) << (27 - i);
            right_key |= key_bit_value;
        }

        for round in 1..=16 {
            let shift_amount = key_shifts[round];
            left_key = ((left_key << shift_amount) | (left_key >> (28 - shift_amount))) & 0xFFFFFFF;
            right_key = ((right_key << shift_amount) | (right_key >> (28 - shift_amount))) & 0xFFFFFFF;

            // Now pick subkeys using PC_2:
            for (i, v) in PC_2.iter().enumerate() {

            }
        }   
    }

    pub fn new(key: u64) {}

    pub fn encrypt() {}

    pub fn decrypt() {}
}
