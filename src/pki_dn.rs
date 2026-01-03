// Copyright 2026 Andreas Steffen
// Copyright 2015 Tobias Brunner
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
// Extract subject DN.
//
pub fn pki_dn() -> i32
{
    println!("dn()");
    return 0;
}

//
// Register the command.
//
inventory::submit!
{
    let brief: &'static[&'static str] = &[
        "[--in file] [--format config|hex|base64|bin]"
    ];
    let options: &'static[Opt] = &[
        Opt { long: "help",   short: "h", arg: 0, descr: "show usage information" },
        Opt { long: "in",     short: "i", arg: 1, descr: "input file, default: stdin" },
        Opt { long: "format", short: "f", arg: 1, descr: "output format, default: config" },
];
    Command::new(pki_dn, "d", "dn",
                "extract the subject DN of an X.509 certificate", brief, options)
}
