use crate::hash::HashType;
use std::path::PathBuf;

use clap::{
    builder::{EnumValueParser, PathBufValueParser, StringValueParser},
    crate_name, crate_version, Arg, ArgAction, Command,
};

pub fn cli() -> (std::string::String, PathBuf, HashType) {
    let cli = Command::new(crate_name!())
        .about("A simple hash cracking tool built in rust.")
        .version(crate_version!())
        .arg(
            Arg::new("digest")
                .short('d')
                .long("digest")
                .action(ArgAction::Set)
                .value_parser(StringValueParser::new())
                .required(true),
        )
        .arg(
            Arg::new("wordlist")
                .short('w')
                .long("wordlist")
                .action(ArgAction::Set)
                .value_parser(PathBufValueParser::new())
                .required(true),
        )
        .arg(
            Arg::new("hashtype")
                .short('t')
                .long("type")
                .action(ArgAction::Set)
                .value_parser(EnumValueParser::<HashType>::new())
                .required(true),
        )
        .get_matches();

    let digest: String = cli.get_one::<String>("digest").unwrap().to_owned();
    let wordlist: PathBuf = cli.get_one::<PathBuf>("wordlist").unwrap().to_owned();
    let hashtype: HashType = cli.get_one::<HashType>("hashtype").unwrap().to_owned();

    return (digest, wordlist, hashtype);
}
