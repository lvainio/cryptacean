use std::fs;

use rust_crypto::{cli, hash};

fn main() {
    let (digest, wordlist, hashtype) = cli::cli();

    let path = wordlist.as_path();
    let words: String = fs::read_to_string(path).unwrap();

    let hasher = hash::Hasher::new(hashtype);

    hasher.run(&words, &digest);
}
