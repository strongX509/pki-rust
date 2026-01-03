// Copyright 2015-2026 Andreas Steffen
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
use pki::Command;
use pki::Opt;

//
// Issue an attribute certificate,
//
pub fn pki_acert(matches: &Matches) -> ExitCode
{
    let issuercert = match matches.opt_str("c") {
        Some(v) => { v }
        None => {
            println!("option '--issuercert' is required");
            return ExitCode::from(2);
        }
    };
    println!("option: --issuercert {}", issuercert);

    let issuerkey = match matches.opt_str("k") {
        Some(v) => { v }
        None => { "".to_string() }
    };
    println!("option: --issuerkey {}", issuerkey);

    let issuerkeyid = match matches.opt_str("x") {
        Some(v) => { v }
        None => { "".to_string() }
    };
    println!("option: --issuerkeyid {}", issuerkeyid);

    if issuerkey.is_empty() && issuerkeyid.is_empty() {
        println!("option '--issuerkey' or '--issuerkeyid' is required");
        return ExitCode::from(2);
    }

    if !issuerkey.is_empty() && !issuerkeyid.is_empty() {
        println!("options '--issuerkey' and '--issuerkeyid' can't be set both");
        return ExitCode::from(2);
    }

    if matches.opt_present("i") {
        let file = matches.opt_str("i").unwrap();
        println!("option: --in {}", file);
    } else {
        println!("option '--in' missing: get input from stdin");
    }

    let groups: Vec<String> = matches.opt_strs("m");
    for g in &groups
    {
        println!("option: --group {}", g);
    }

    if matches.opt_present("s") {
        let serial = matches.opt_str("s").unwrap();
        println!("option: --serial {}", serial);
    }

    if matches.opt_present("l") {
        let lifetime = matches.opt_str("l").unwrap();
        println!("option: --lifetime {}", lifetime);
    }

    if matches.opt_present("F") {
        let datenb = matches.opt_str("F").unwrap();
        println!("option: --not-before {}", datenb);
    }

    if matches.opt_present("T") {
        let datena = matches.opt_str("T").unwrap();
        println!("option: --not-after {}", datena);
    }

    if matches.opt_present("D") {
        let dateform = matches.opt_str("D").unwrap();
        println!("option: --dateform {}", dateform);
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

    println!("acert()");
    return ExitCode::SUCCESS;
}

//
// Register the command.
//
inventory::submit!
{
    let brief: &'static[&'static str] = &[
        "[--in file] [--group name]+ --issuerkey file|--issuerkeyid hex",
        " --issuercert file [--serial hex] [--lifetime hours]",
        "[--not-before datetime] [--not-after datetime] [--dateform form]",
        "[--digest md5|sha1|sha224|sha256|sha384|sha512|sha3_224|sha3_256|sha3_384|sha3_512]",
        "[--rsa-padding pkcs1|pss] [--outform der|pem]"
    ];
    let options: &'static[Opt] = &[
        Opt { long: "help"       , short: "h", arg: 0, descr: "show usage information" },
        Opt { long: "in"         , short: "i", arg: 1, descr: "holder certificate, default: stdin" },
        Opt { long: "group"      , short: "m", arg: 2, descr: "group membership string to include" },
        Opt { long: "issuercert" , short: "c", arg: 1, descr: "issuer certificate file" },
        Opt { long: "issuerkey"  , short: "k", arg: 1, descr: "issuer private key file" },
        Opt { long: "issuerkeyid", short: "x", arg: 1, descr: "smartcard or TPM issuer private key object handle" },
        Opt { long: "serial"     , short: "s", arg: 1, descr: "serial number in hex, default: random" },
        Opt { long: "lifetime"   , short: "l", arg: 1, descr: "hours the acert is valid, default: 24" },
        Opt { long: "not-before" , short: "F", arg: 1, descr: "date/time the validity of the AC starts" },
        Opt { long: "not-after"  , short: "T", arg: 1, descr: "date/time the validity of the AC ends" },
        Opt { long: "dateform"   , short: "D", arg: 1, descr: "strptime(3) input format, default: %d.%m.%y %T" },
        Opt { long: "digest"     , short: "g", arg: 1, descr: "digest for signature creation, default: key-specific" },
        Opt { long: "rsa-padding", short: "R", arg: 1, descr: "padding for RSA signatures, default: pkcs1" },
        Opt { long: "outform"    , short: "f", arg: 1, descr: "encoding of generated cert, default: der" },
    ];
    Command::new(pki_acert, "z", "acert",
                "issue an attribute certificate", brief, options)
}
