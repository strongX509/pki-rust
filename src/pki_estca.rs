// Copyright 2022-2026 Andreas Steffen
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
// Get CA certificate[s] from an EST server (RFC 7030).
//
pub fn pki_estca(matches: &Matches) -> ExitCode
{
    if matches.opt_present("u") {
        let url = matches.opt_str("u").unwrap();
        println!("option: --url {}", url);
    } else {
        println!("option '--url' is required");
        return ExitCode::from(2);
    }

    let cacerts: Vec<String> = matches.opt_strs("C");
    for c in &cacerts {
         println!("option: --cacert {}", c);
    }
    if cacerts.len() == 0 {
        println!("option '--cacert' is required");
        return ExitCode::from(2);
    }

    if matches.opt_present("l") {
        let label = matches.opt_str("l").unwrap();
        println!("option: --label {}", label);
    }

    if matches.opt_present("c") {
        let caout = matches.opt_str("c").unwrap();
        println!("option: --caout {}", caout);
    }

    if matches.opt_present("f") {
        let form = matches.opt_str("f").unwrap();
        println!("option: --outform {}", form);
    }

    let force: bool = matches.opt_present("F");
    println!("force:  {}", force);

    println!("estca()");
    return ExitCode::SUCCESS;
}

//
// Register the command.
//
inventory::submit!
{
    let brief: &'static[&'static str] = &[
        "--url url [--label label] --cacert file+ [--caout file]",
        "[--outform der|pem] [--force]"
    ];
    let options: &'static[Opt] = &[
        Opt { long: "help",    short: "h", arg: 0, descr: "show usage information" },
        Opt { long: "url",     short: "u", arg: 1, descr: "URL of the EST server" },
        Opt { long: "label",   short: "l", arg: 1, descr: "label in the EST server path" },
        Opt { long: "cacert",  short: "C", arg: 2, descr: "TLS CA certificate(s)" },
        Opt { long: "caout",   short: "c", arg: 1, descr: "CA certificate [template]" },
        Opt { long: "outform", short: "f", arg: 1, descr: "encoding of stored certificates, default: der" },
        Opt { long: "force",   short: "F", arg: 0, descr: "force overwrite of existing files" },
    ];
    Command::new(pki_estca, "e", "estca",
                "get CA certificate[s] from an EST server", brief, options)
}
