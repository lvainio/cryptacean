use std::time::Instant;

use crate::hash::md5::hash;

pub mod hash;

fn main() {
    let start = Instant::now();

    let input: String = "rust".repeat(10_000);

    let input = input.trim().as_bytes();

    let hashi = hash(input);

    let duration = start.elapsed();

    println!("Time elapsed: {:?}", duration);
    println!("Time elapsed: {}", hashi);
}
