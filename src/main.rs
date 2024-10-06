use std::io;

const BLOCK_SIZE: u64 = 512;

const INIT_A: u32 = 0x67_45_23_01;
const INIT_B: u32 = 0xEF_CD_AB_89;
const INIT_C: u32 = 0x98_BA_DC_FE;
const INIT_D: u32 = 0x10_32_54_76;

const T: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
];

const S: [u32; 64] = [
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22, 
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20, 
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23, 
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21 
];

const K: [usize; 64] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
    5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
    0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9,
];

/// Pad input bytes according to MD5 specification.
fn pad(input: &[u8]) -> Vec<u8> {


    println!("{:?}", input);
    println!("{}", input.len());

    let input_length: u64 = input.len() as u64;
    let input_length_in_bits: u64 = input_length * 8;
    let length_le_bytes: [u8; 8] = input_length_in_bits.to_le_bytes(); 

    println!("bits {}", input_length_in_bits);
    println!("{:?}", length_le_bytes);

    let input_length_mod_64: u64 = input_length % 64;
    let padding_length: u64 = match input_length_mod_64 {            
        56 => 64,                           
        _ => (56 + 64 - input_length_mod_64) % 64
    };

    let total_length = (input_length + padding_length + 8) as usize;
    let mut buffer: Vec<u8> = Vec::with_capacity(total_length);

    buffer.extend_from_slice(input);
    buffer.push(0x80);
    buffer.resize((input_length + padding_length) as usize, 0x00);
    buffer.extend_from_slice(&length_le_bytes);

    buffer
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

fn md5(input: &[u8]) -> [u8; 16] {
    let padded_input = pad(input);

    println!("{:?}", padded_input);

    let n = padded_input.len() / (BLOCK_SIZE / 8) as usize;

    let mut a = INIT_A;
    let mut b = INIT_B;
    let mut c = INIT_C;
    let mut d = INIT_D;

    for i in 0..n {
        let mut x: [u32; 16] = [0; 16];
        for j in 0..16 {
            x[j] = u32::from_le_bytes([
                padded_input[i*64 + j * 4],
                padded_input[i*64 + j * 4 + 1],
                padded_input[i*64 + j * 4 + 2],
                padded_input[i*64 + j * 4 + 3]
            ]);
        }

        let aa = a;
        let bb = b;
        let cc = c;
        let dd = d;

        let mut rnd: usize = 0;

        // Round 1
        for _ in 0..4 {
            a = b.wrapping_add(
                a.wrapping_add(f_transform(b, c, d))
                .wrapping_add(x[K[rnd]])
                .wrapping_add(T[rnd]).rotate_left(S[rnd])
            );
            rnd += 1;
            d = a.wrapping_add(
                d.wrapping_add(f_transform(a, b, c))
                .wrapping_add(x[K[rnd]])
                .wrapping_add(T[rnd]).rotate_left(S[rnd])
            );
            rnd += 1;
            c = d.wrapping_add(
                c.wrapping_add(f_transform(d, a, b))
                .wrapping_add(x[K[rnd]])
                .wrapping_add(T[rnd]).rotate_left(S[rnd])
            );
            rnd += 1;
            b = c.wrapping_add(
                b.wrapping_add(f_transform(c, d, a))
                .wrapping_add(x[K[rnd]])
                .wrapping_add(T[rnd]).rotate_left(S[rnd])
            );
            rnd += 1;
        }

        // Round 2
        for _ in 0..4 {
            a = b.wrapping_add(
                a.wrapping_add(g_transform(b, c, d))
                .wrapping_add(x[K[rnd]])
                .wrapping_add(T[rnd]).rotate_left(S[rnd])
            );
            rnd += 1;
            d = a.wrapping_add(
                d.wrapping_add(g_transform(a, b, c))
                .wrapping_add(x[K[rnd]])
                .wrapping_add(T[rnd]).rotate_left(S[rnd])
            );
            rnd += 1;
            c = d.wrapping_add(
                c.wrapping_add(g_transform(d, a, b))
                .wrapping_add(x[K[rnd]])
                .wrapping_add(T[rnd]).rotate_left(S[rnd])
            );
            rnd += 1;
            b = c.wrapping_add(
                b.wrapping_add(g_transform(c, d, a))
                .wrapping_add(x[K[rnd]])
                .wrapping_add(T[rnd]).rotate_left(S[rnd])
            );
            rnd += 1;
        }

        // Round 3
        for _ in 0..4 {
            a = b.wrapping_add(
                a.wrapping_add(h_transform(b, c, d))
                .wrapping_add(x[K[rnd]])
                .wrapping_add(T[rnd]).rotate_left(S[rnd])
            );
            rnd += 1;
            d = a.wrapping_add(
                d.wrapping_add(h_transform(a, b, c))
                .wrapping_add(x[K[rnd]])
                .wrapping_add(T[rnd]).rotate_left(S[rnd])
            );
            rnd += 1;
            c = d.wrapping_add(
                c.wrapping_add(h_transform(d, a, b))
                .wrapping_add(x[K[rnd]])
                .wrapping_add(T[rnd]).rotate_left(S[rnd])
            );
            rnd += 1;
            b = c.wrapping_add(
                b.wrapping_add(h_transform(c, d, a))
                .wrapping_add(x[K[rnd]])
                .wrapping_add(T[rnd]).rotate_left(S[rnd])
            );
            rnd += 1;
        }

        // Round 4
        for _ in 0..4 {
            a = b.wrapping_add(
                a.wrapping_add(i_transform(b, c, d))
                .wrapping_add(x[K[rnd]])
                .wrapping_add(T[rnd]).rotate_left(S[rnd])
            );
            rnd += 1;
            d = a.wrapping_add(
                d.wrapping_add(i_transform(a, b, c))
                .wrapping_add(x[K[rnd]])
                .wrapping_add(T[rnd]).rotate_left(S[rnd])
            );
            rnd += 1;
            c = d.wrapping_add(
                c.wrapping_add(i_transform(d, a, b))
                .wrapping_add(x[K[rnd]])
                .wrapping_add(T[rnd]).rotate_left(S[rnd])
            );
            rnd += 1;
            b = c.wrapping_add(
                b.wrapping_add(i_transform(c, d, a))
                .wrapping_add(x[K[rnd]])
                .wrapping_add(T[rnd]).rotate_left(S[rnd])
            );
            rnd += 1;
        }

        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);
    }

    let a_bytes = a.to_le_bytes();
    let b_bytes = b.to_le_bytes();
    let c_bytes = c.to_le_bytes();
    let d_bytes = d.to_le_bytes();

    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&a_bytes);
    bytes[4..8].copy_from_slice(&b_bytes);
    bytes[8..12].copy_from_slice(&c_bytes);
    bytes[12..16].copy_from_slice(&d_bytes);

    bytes
}


fn main() {
    let mut password: String = String::new();

    println!("Enter your password: ");
    io::stdin()
        .read_line(&mut password)
        .expect("Failed to read password");
    let password_bytes = password.trim().as_bytes();

    let my_md5_hash = md5(password_bytes);

    let hex_string: String = my_md5_hash.iter().map(|byte| format!("{:02x}", byte)).collect();
    
    println!("Hex: {}", hex_string);
}