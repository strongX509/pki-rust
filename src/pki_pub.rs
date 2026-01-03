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
// Extract a public key from a private key/certificate.
//
pub fn pki_pub() -> i32
{
    println!("pub()");
    return 0;
}

//
// Register the command.
//
inventory::submit!
{
    let brief: &'static[&'static str] = &[
        "[--in file|--keyid hex] [--type rsa|ecdsa|priv|pub|pkcs10|x509]",
        "[--outform der|pem|dnskey|sshkey]"
    ];
    let options: &'static[Opt] = &[
        Opt { long: "help",    short: "h", arg: 0, descr: "show usage information" },
        Opt { long: "in",      short: "i", arg: 1, descr: "input file, default: stdin" },
        Opt { long: "keyid",   short: "x", arg: 1, descr: "smartcard or TPM private key object handle" },
        Opt { long: "type",    short: "t", arg: 1, descr: "type of credential, default: priv" },
        Opt { long: "outform", short: "f", arg: 1, descr: "encoding of extracted public key, default: der" },
    ];
    Command::new(pki_pub, "p", "pub",
                "extract the public key from a private key/certificate", brief, options)
}
