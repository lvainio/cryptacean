use std::fs;

use rust_hash_cracker::{cli, hash};

use rust_hash_cracker::cipher::rsa;

fn main() {
    let rsa_cipher = rsa::RSA::new();

    let (digest, wordlist, hashtype) = cli::cli();

    let path = wordlist.as_path();
    let words: String = fs::read_to_string(path).unwrap();

    let hasher = hash::Hasher::new(hashtype);

    hasher.run(&words, &digest);
}
