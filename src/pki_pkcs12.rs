// Copyright 2026 Andreas Steffen
// Copyright 2014 Tobias Brunner
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
// Show info about PKCS#12 container.
//
pub fn pki_pkcs12(matches: &Matches) -> ExitCode
{
    if matches.opt_present("i") {
        let file = matches.opt_str("i").unwrap();
        println!("option: --in {}", file);
    } else {
        println!("option '--in' missing: get input from stdin");
    }

    let list: bool = matches.opt_present("l");
    println!("list: {}", list);

    if matches.opt_present("e") {
        let export = matches.opt_str("e").unwrap();
        println!("option: --export {}", export);
    }

    if matches.opt_present("f") {
        let form = matches.opt_str("f").unwrap();
        println!("option: --outform {}", form);
    }

    println!("pkcs12()");
    return ExitCode::SUCCESS;
}

//
// Register the command.
//
inventory::submit!
{
    let brief: &'static[&'static str] = &[
        "--export index|--list [--in file]",
        "[--outform der|pem]"
    ];
    let options: &'static[Opt] = &[
        Opt { long: "help",    short: "h", arg: 0, descr: "show usage information" },
        Opt { long: "in",      short: "i", arg: 1, descr: "input file, default: stdin" },
        Opt { long: "list",    short: "l", arg: 0, descr: "list certificates and keys" },
        Opt { long: "export",  short: "e", arg: 1, descr: "export the credential with the given index" },
        Opt { long: "outform", short: "f", arg: 1, descr: "encoding of exported credentials, default: der" },
    ];
    Command::new(pki_pkcs12, "u", "pkcs12",
                "PKCS#12 functions", brief, options)
}
