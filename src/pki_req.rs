// Copyright 2009-2026 Andreas Steffen
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
// Create a self-signed PKCS#10 certificate request..
//
pub fn pki_req(matches: &Matches) -> ExitCode
{
   let file = match matches.opt_str("i") {
        Some(v) => { v }
        None => { "".to_string() }
    };
    println!("option: --in {}", file);

    let keyid = match matches.opt_str("x") {
        Some(v) => { v }
        None => { "".to_string() }
    };
    println!("option: --keyid {}", keyid);

    if !file.is_empty() && !keyid.is_empty() {
        println!("options '--in' and '--keyid' can't be set both");
        return ExitCode::SUCCESS;
    }

    if file.is_empty() && keyid.is_empty() {
        println!("option '--in' or '--keyid' missing: get input from stdin");
    }

    let in_type = match matches.opt_str("t") {
        Some(t) => {
            if t == "rsa" {
                KeyType::RSA
            } else if t == "ecdsa" {
                KeyType::ECDSA
            } else if t == "priv" {
                KeyType::ANY
            } else {
                println!("invalid input type");
                return ExitCode::from(2);
            }
        }
        None => { KeyType::RSA }
    };
    println!("option: --type {:?}", in_type);

    if matches.opt_present("o") {
        let oldreq = matches.opt_str("o").unwrap();
        println!("option: --oldreq {}", oldreq);
    }

    if matches.opt_present("d") {
        let dn = matches.opt_str("d").unwrap();
        println!("option: --dn {}", dn);
    }

    let san: Vec<String> = matches.opt_strs("a");
    for s in &san
    {
        println!("option: --san {}", s);
    }

    let flags: Vec<String> = matches.opt_strs("e");
    for f in &flags
     {
            println!("option: --flag {}", f);
    }

    if matches.opt_present("P") {
        let profile = matches.opt_str("P").unwrap();
        println!("option: --profile {}", profile);
    }

    if matches.opt_present("p") {
        let password = matches.opt_str("p").unwrap();
        println!("option: --password {}", password);
    }

    if matches.opt_present("g") {
        let digest = matches.opt_str("g").unwrap();
        println!("option: --digest {}", digest);
    }

    if matches.opt_present("R") {
        let padding = matches.opt_str("R").unwrap();
        println!("option: --rsa-padding {}", padding);
    }

    if matches.opt_present("f") {
        let form = matches.opt_str("f").unwrap();
        println!("option: --outform {}", form);
    }

    println!("req()");
    return ExitCode::SUCCESS;
}

//
// Register the command.
//
inventory::submit!
{
    let brief: &'static[&'static str] = &[
        "[--in file|--keyid hex] [--type rsa|ecdsa|priv]",
        " --oldreq file|--dn distinguished-name [--san subjectAltName]+",
        "[--flag serverAuth|clientAuth|ocspSigning|msSmartcardLogon]+",
        "[--profile server|client|dual|ocsp] [--password challengePassword]",
        "[--digest sha1|sha224|sha256|sha384|sha512|sha3_224|sha3_256|sha3_384|sha3_512]",
        "[--rsa-padding pkcs1|pss] [--outform der|pem]"
    ];
    let options: &'static[Opt] = &[
        Opt { long: "help",        short: "h", arg: 0, descr: "show usage information" },
        Opt { long: "in",          short: "i", arg: 1, descr: "private key input file, default: stdin" },
        Opt { long: "keyid",       short: "x", arg: 1, descr: "smartcard or TPM private key object handle" },
        Opt { long: "type",        short: "t", arg: 1, descr: "type of input key, default: priv" },
        Opt { long: "oldreq",      short: "o", arg: 1, descr: "old certificate request to be used as a template" },
        Opt { long: "dn",          short: "d", arg: 1, descr: "subject distinguished name" },
        Opt { long: "san",         short: "a", arg: 2, descr: "subjectAltName to include in cert request" },
        Opt { long: "flag",        short: "e", arg: 2, descr: "include extendedKeyUsage flag" },
        Opt { long: "profile",     short: "P", arg: 1, descr: "certificate profile name to include in cert request" },
        Opt { long: "password",    short: "p", arg: 1, descr: "challengePassword to include in cert request" },
        Opt { long: "digest",      short: "g", arg: 1, descr: "digest for signature creation, default: key-specific" },
        Opt { long: "rsa-padding", short: "R", arg: 1, descr: "padding for RSA signatures, default: pkcs1" },
        Opt { long: "outform",     short: "f", arg: 1, descr: "encoding of generated request, default: der" },
    ];
    Command::new(pki_req, "r", "req",
                "create a PKCS#10 certificate request", brief, options)
}
