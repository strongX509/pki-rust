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

use pki::Command;
use pki::Opt;

//
// Print a single keyid in the requested format.
//
pub fn pki_keyid() -> i32
{
    println!("keyid()");
    return 0;
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
