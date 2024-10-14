use std::fs;

use rust_hash_cracker::cli;
use rust_hash_cracker::hash::HashFunction;

fn main() {
    let (digest, wordlist, hashtype) = cli::cli();

    let path = wordlist.as_path();

    let contents: String = fs::read_to_string(path).unwrap();

    let md5 = rust_hash_cracker::hash::md5::MD5;

    let lines = contents.lines();

    for word in lines {
        let input = rust_hash_cracker::hash::Input::from_string(word);

        let dig = md5.hash(&input).output;

        if digest == dig {
            println!("found match: {word}");
            println!("hash(word) = {dig}");
            println!("digest = {digest}");
            break;
        }
    }
}
