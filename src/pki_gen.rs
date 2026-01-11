// Copyright 2014-2026 Andreas Steffen
// Copyright 2009 Martin Willi
//
// Copyright secunet Security Networks AG
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2 of the License, or (at your
// option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
// for more details.

use std::process::ExitCode;
use getopts::Matches;
use pki::{Command, Opt};
use pki::strongswan::keys::KeyType;

//
// Generate a private key.
//
pub fn pki_gen(matches: &Matches) -> ExitCode
{
    let key_type = match matches.opt_str("t") {
        Some(t) => {
            if t == "rsa" {
                KeyType::RSA
            } else if t == "ecdsa" {
                KeyType::ECDSA
            } else if t == "ed25519" {
                KeyType::ED25519
            } else if t == "ed448" {
                KeyType::ED448
            } else {
                println!("invalid key type");
                return ExitCode::from(2);
            }
        }
        None => { KeyType::RSA }
    };
    println!("option: --type {:?}", key_type);

    let size: u32 = match matches.opt_str("s") {
        Some(string) => { string.parse().unwrap() }
        None => { 0 } // bits
    };
    println!("option: --size {} bits", size);

    if matches.opt_present("f") {
        let form = matches.opt_str("f").unwrap();
        println!("option: --outform {}", form);
    }

    println!("gen()");
    return ExitCode::SUCCESS;
}

//
// Register the command.
//
inventory::submit!
{
    let brief: &'static[&'static str] = &[
        "[--type rsa|ecdsa|ed25519|ed448] [--size bits] [--safe-primes]",
        "[--shares n] [--threshold l] [--outform der|pem]"
    ];
    let options: &'static[Opt] = &[
        Opt { long: "help",        short: "h", arg: 0, descr: "show usage information" },
        Opt { long: "type",        short: "t", arg: 1, descr: "type of key, default: rsa" },
        Opt { long: "size",        short: "s", arg: 1, descr: "keylength in bits, default: rsa 2048, ecdsa 384" },
        Opt { long: "outform",     short: "f", arg: 1, descr: "encoding of generated private key, default: der" },
    ];
    Command::new(pki_gen, "g", "gen",
                "generate a new private key", brief, options)
}
