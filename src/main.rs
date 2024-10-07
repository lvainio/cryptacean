use std::time::Instant;

use crate::hash::md5::hash;

pub mod hash;

fn main() {

    let start = Instant::now();

    let input: String = String::from("input");

    let input = input.trim().as_bytes();

    for _ in 0..1000000 {
        hash(input);
    }

    let duration = start.elapsed();

    println!("Time elapsed: {:?}", duration);
}