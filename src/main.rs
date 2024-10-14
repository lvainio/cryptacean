use std::fs;

use rust_hash_cracker::{
    cli,
    hash::{self, HashFunction},
};

fn main() {
    let (digest, wordlist, hashtype) = cli::cli();

    let path = wordlist.as_path();
    let words: String = fs::read_to_string(path).unwrap();

    let hasher = hash::Hasher::new(hashtype);

    hasher.run(&words, &digest);

    // testing

    let sha1 = rust_hash_cracker::hash::sha1::SHA1;

    let input = rust_hash_cracker::hash::Input::from_string("abc");

    let hash = sha1.hash(&input);

    println!("{}", hash.output);
}
