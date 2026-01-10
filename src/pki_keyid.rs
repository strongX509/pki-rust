// Copyright 2017-2026 Andreas Steffen
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

//
// Print a single keyid in the requested format.
//
pub fn pki_keyid(matches: &Matches) -> ExitCode
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

    if matches.opt_present("t") {
        let in_type = matches.opt_str("t").unwrap();
        println!("option: --type {}", in_type);
    }

    if matches.opt_present("I") {
        let id_type = matches.opt_str("I").unwrap();
        println!("option: --id {}", id_type);
    }

    if matches.opt_present("f") {
        let format = matches.opt_str("f").unwrap();
        println!("option: --format {}", format);
    }

    println!("keyid()");
    return ExitCode::SUCCESS;
}

//
// Register the command.
//
inventory::submit!
{
    let brief: &'static[&'static str] = &[
        "[--in file|--keyid hex] [--type priv|rsa|ecdsa|pub|pkcs10|x509]",
        "[--id all|spk|spki] [--format pretty|hex|base64|bin]"
    ];
    let options: &'static[Opt] = &[
        Opt { long: "help",   short: "h", arg: 0, descr: "show usage information" },
        Opt { long: "in",     short: "i", arg: 1, descr: "input file, default: stdin" },
        Opt { long: "keyid",  short: "x", arg: 1, descr: "smartcard or TPM private key object handle" },
        Opt { long: "type",   short: "t", arg: 1, descr: "type of key, default: priv" },
        Opt { long: "id",     short: "I", arg: 1, descr: "type of identifier, default: all" },
        Opt { long: "format", short: "f", arg: 1, descr: "output format, default: pretty" },
    ];
    Command::new(pki_keyid, "k", "keyid",
                "calculate key identifiers of a key/certificate", brief, options)
}
