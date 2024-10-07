use std::io;

use crate::hash::md5::hash;

pub mod hash;

fn main() {
    let mut password: String = String::new();

    println!("Enter your password: ");
    io::stdin()
        .read_line(&mut password)
        .expect("Failed to read password");
    let password_bytes = password.trim().as_bytes();

    let my_hash = hash(password_bytes);
    
    println!("Hex: {}", my_hash);
}