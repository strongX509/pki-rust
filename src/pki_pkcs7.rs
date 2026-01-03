// Copyright 2026 Andreas Steffen
// Copyright 2012 Martin Willi
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
use pki::Command;
use pki::Opt;

//
// Wrap/Unwrap PKCs#7 containers.
//
pub fn pki_pkcs7(matches: &Matches) -> ExitCode
{
    if matches.opt_present("i") {
        let file = matches.opt_str("i").unwrap();
        println!("option: --in {}", file);
    } else {
        println!("option '--in' missing: get input from stdin");
    }

    let sign: bool = matches.opt_present("s");
    println!("sign:    {}", sign);

    let verify: bool = matches.opt_present("u");
    println!("verify:  {}", verify);

    let encrypt: bool = matches.opt_present("e");
    println!("encrypt: {}", encrypt);

    let decrypt: bool = matches.opt_present("d");
    println!("decrypt: {}", decrypt);

    let show: bool = matches.opt_present("p");
    println!("show:    {}", show);

    let key = match matches.opt_str("k") {
        Some(v) => { v }
        None => { "".to_string() }
    };
    println!("option: --key {}", key);

    let cert = match matches.opt_str("c") {
        Some(v) => { v }
        None => { "".to_string() }
    };
    println!("option: --cert {}", cert);

    if matches.opt_present("g") {
        let digest = matches.opt_str("g").unwrap();
        println!("option: --digest {}", digest);
    }

    if matches.opt_present("R") {
        let padding = matches.opt_str("R").unwrap();
        println!("option: --rsa-padding {}", padding);
    }

    println!("pkcs7()");
    return ExitCode::SUCCESS;
}

//
// Register the command.
//
inventory::submit!
{
    let brief: &'static[&'static str] = &[
        "--sign|--verify|--encrypt|--decrypt|--show",
        "[--in file] [--cert file]+ [--key file]",
        "[--digest md5|sha1|sha224|sha256|sha384|sha512|sha3_224|sha3_256|sha3_384|sha3_512]",
        "[--rsa-padding pkcs1|pss]"
    ];
    let options: &'static[Opt] = &[
        Opt { long: "help",        short: "h", arg: 0, descr: "show usage information" },
        Opt { long: "sign",        short: "s", arg: 0, descr: "create PKCS#7 signed-data" },
        Opt { long: "verify",      short: "u", arg: 0, descr: "verify PKCS#7 signed-data" },
        Opt { long: "encrypt",     short: "e", arg: 0, descr: "create PKCS#7 enveloped-data" },
        Opt { long: "decrypt",     short: "d", arg: 0, descr: "decrypt PKCS#7 enveloped-data" },
        Opt { long: "show",        short: "p", arg: 0, descr: "show info about PKCS#7, print certificates" },
        Opt { long: "in",          short: "i", arg: 1, descr: "input file, default: stdin" },
        Opt { long: "key",         short: "k", arg: 1, descr: "path to private key for sign/decrypt" },
        Opt { long: "cert",        short: "c", arg: 1, descr: "path to certificate for sign/verify/encrypt" },
        Opt { long: "digest",      short: "g", arg: 1, descr: "digest for signature creation, default: key-specific" },
        Opt { long: "rsa-padding", short: "R", arg: 1, descr: "padding for RSA signatures, default: pkcs1" },
    ];
    Command::new(pki_pkcs7, "7", "pkcs7",
                "PKCS#7 wrap/unwrap functions", brief, options)
}
