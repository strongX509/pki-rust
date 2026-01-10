// Copyright 2022-2026 Andreas Steffen
// Copyright 2012 Tobias Brunner
// Copyright 2005 Jan Hutter, Martin Willi
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
// Get CA certificate[s] from a SCEP server (RFC 8894).
//
pub fn pki_scepca(matches: &Matches) -> ExitCode
{
    if matches.opt_present("u") {
        let url = matches.opt_str("u").unwrap();
        println!("option: --url {}", url);
    } else {
        println!("option '--url' is required");
        return ExitCode::from(2);
    }

    if matches.opt_present("c") {
        let caout = matches.opt_str("c").unwrap();
        println!("option: --caout {}", caout);
    }

    if matches.opt_present("r") {
        let raout = matches.opt_str("r").unwrap();
        println!("option: --raout {}", raout);
    }

    if matches.opt_present("f") {
        let form = matches.opt_str("f").unwrap();
        println!("option: --outform {}", form);
    }

    let force: bool = matches.opt_present("F");
    println!("force:  {}", force);

    println!("scepca()");
    return ExitCode::SUCCESS;
}

//
// Register the command.
//
inventory::submit!
{
    let brief: &'static[&'static str] = &[
        "--url url [--caout file] [--raout file] [--outform der|pem] [--force]"
    ];
    let options: &'static[Opt] = &[
        Opt { long: "help",    short: "h", arg: 0, descr: "show usage information" },
        Opt { long: "url",     short: "u", arg: 1, descr: "URL of the SCEP server" },
        Opt { long: "caout",   short: "c", arg: 1, descr: "CA certificate [template]" },
        Opt { long: "raout",   short: "r", arg: 1, descr: "RA certificate [template]" },
        Opt { long: "outform", short: "f", arg: 1, descr: "encoding of stored certificates, default: der" },
        Opt { long: "force",   short: "F", arg: 0, descr: "force overwrite of existing files" },
    ];
    Command::new(pki_scepca, "C", "scepca",
                "get CA [and RA] certificate[s] from a SCEP server", brief, options)
}
