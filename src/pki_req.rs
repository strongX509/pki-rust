// Copyright 2009-2026 Andreas Steffen
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
// Create a self-signed PKCS#10 certificate request..
//
pub fn pki_req() -> i32
{
    println!("req()");
    return 0;
}

//
// Register the command.
//
inventory::submit!
{
    let brief: &'static[&'static str] = &[
        "[--in file|--keyid hex] [--type rsa|ecdsa|priv]",
        " --oldreq file|--dn distinguished-name [--san subjectAltName]+",
        "[--flag serverAuth|clientAuth|ocspSigning|msSmartcardLogon]+",
        "[--profile server|client|dual|ocsp] [--password challengePassword]",
        "[--digest sha1|sha224|sha256|sha384|sha512|sha3_224|sha3_256|sha3_384|sha3_512]",
        "[--rsa-padding pkcs1|pss] [--outform der|pem]"
    ];
    let options: &'static[Opt] = &[
        Opt { long: "help",        short: "h", arg: 0, descr: "show usage information" },
        Opt { long: "in",          short: "i", arg: 1, descr: "private key input file, default: stdin" },
        Opt { long: "keyid",       short: "x", arg: 1, descr: "smartcard or TPM private key object handle" },
        Opt { long: "type",        short: "t", arg: 1, descr: "type of input key, default: priv" },
        Opt { long: "oldreq",      short: "o", arg: 1, descr: "old certificate request to be used as a template" },
        Opt { long: "dn",          short: "d", arg: 1, descr: "subject distinguished name" },
        Opt { long: "san",         short: "a", arg: 1, descr: "subjectAltName to include in cert request" },
        Opt { long: "flag",        short: "e", arg: 1, descr: "include extendedKeyUsage flag" },
        Opt { long: "profile",     short: "P", arg: 1, descr: "certificate profile name to include in cert request" },
        Opt { long: "password",    short: "p", arg: 1, descr: "challengePassword to include in cert request" },
        Opt { long: "digest",      short: "g", arg: 1, descr: "digest for signature creation, default: key-specific" },
        Opt { long: "rsa-padding", short: "R", arg: 1, descr: "padding for RSA signatures, default: pkcs1" },
        Opt { long: "outform",     short: "f", arg: 1, descr: "encoding of generated request, default: der" },
    ];
    Command::new(pki_req, "r", "req",
                "create a PKCS#10 certificate request", brief, options)
}
