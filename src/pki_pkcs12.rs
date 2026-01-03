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

use pki::Command;
use pki::Opt;

//
// Show info about PKCS#12 container.
//
pub fn pki_pkcs12() -> i32
{
    println!("pkcs12()");
    return 0;
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
