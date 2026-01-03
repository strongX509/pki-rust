// Copyright 2015-2026 Andreas Steffen
// Copyright 2010 Martin Willi
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
// Print a credential in a human readable form.
//
pub fn pki_print() -> i32
{
    println!("print()");
    return 0;
}

//
// Register the command.
//
inventory::submit!
{
    let brief: &'static[&'static str] = &[
        "[--in file|--keyid hex]",
        "[--type x509|crl|ac|pub|priv|rsa|ecdsa|ed25519|ed448|ocsp-req|ocsp-rsp]"
    ];
    let options: &'static[Opt] = &[
        Opt { long: "help",  short: "h", arg: 0, descr: "show usage information" },
        Opt { long: "in",    short: "i", arg: 1, descr: "input file, default: stdin" },
        Opt { long: "keyid", short: "x", arg: 1, descr: "smartcard or TPM object handle" },
        Opt { long: "type",  short: "t", arg: 1, descr: "type of credential, default: x509" },
    ];
    Command::new(pki_print, "a", "print",
                "print a credential in a human readable form", brief, options)
}
