// Copyright 2026 Andreas Steffen
// Copyright 2016-2018 Tobias Brunner
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
// Verify a certificate signature.
//
pub fn pki_verify(matches: &Matches) -> ExitCode
{
    let cacerts: Vec<String> = matches.opt_strs("c");
    for c in &cacerts {
         println!("option: --cacert {}", c);
    }
    if cacerts.len() == 0 {
        println!("option '--cacert' is required");
        return ExitCode::from(2);
    }

    let crls: Vec<String> = matches.opt_strs("l");
    for c in &crls {
         println!("option: --crl {}", c);
    }

    if matches.opt_present("i") {
        let file = matches.opt_str("i").unwrap();
        println!("option: --in {}", file);
    } else {
        println!("option '--in' missing: get input from stdin");
    }

    let online: bool = matches.opt_present("o");
    println!("online: {}", online);

    println!("verify()");
    return ExitCode::SUCCESS;
}

//
// Register the command.
//
inventory::submit!
{
    let brief: &'static[&'static str] = &[
        "[--in file] [--cacert file]+ [--crl file]"
    ];
    let options: &'static[Opt] = &[
        Opt { long: "help",   short: "h", arg: 0, descr: "show usage information" },
        Opt { long: "in",     short: "i", arg: 1, descr: "X.509 certificate to verify, default: stdin" },
        Opt { long: "cacert", short: "c", arg: 2, descr: "CA certificate(s) for trustchain verification" },
        Opt { long: "crl",    short: "l", arg: 2, descr: "CRL(s) for trustchain verification" },
        Opt { long: "online", short: "o", arg: 0, descr: "enable online CRL/OCSP revocation checking" },
    ];
    Command::new(pki_verify, "v", "verify",
                "verify a certificate using one or more CA certificates", brief, options)
}
