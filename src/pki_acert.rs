// Copyright 2015-2026 Andreas Steffen
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
// Issue an attribute certificate,
//
pub fn pki_acert() -> i32
{
    println!("acert()");
    return 0;
}

//
// Register the command.
//
inventory::submit!
{
    let brief: &'static[&'static str] = &[
        "[--in file] [--group name]* --issuerkey file|--issuerkeyid hex",
        " --issuercert file [--serial hex] [--lifetime hours]",
        "[--not-before datetime] [--not-after datetime] [--dateform form]",
        "[--digest md5|sha1|sha224|sha256|sha384|sha512|sha3_224|sha3_256|sha3_384|sha3_512]",
        "[--rsa-padding pkcs1|pss] [--outform der|pem]"
    ];
    let options: &'static[Opt] = &[
        Opt { long: "help"       , short: "h", arg: 0, descr: "show usage information" },
        Opt { long: "in"         , short: "i", arg: 1, descr: "holder certificate, default: stdin" },
        Opt { long: "group"      , short: "m", arg: 1, descr: "group membership string to include" },
        Opt { long: "issuercert" , short: "c", arg: 1, descr: "issuer certificate file" },
        Opt { long: "issuerkey"  , short: "k", arg: 1, descr: "issuer private key file" },
        Opt { long: "issuerkeyid", short: "x", arg: 1, descr: "smartcard or TPM issuer private key object handle" },
        Opt { long: "serial"     , short: "s", arg: 1, descr: "serial number in hex, default: random" },
        Opt { long: "lifetime"   , short: "l", arg: 1, descr: "hours the acert is valid, default: 24" },
        Opt { long: "not-before" , short: "F", arg: 1, descr: "date/time the validity of the AC starts" },
        Opt { long: "not-after"  , short: "T", arg: 1, descr: "date/time the validity of the AC ends" },
        Opt { long: "dateform"   , short: "D", arg: 1, descr: "strptime(3) input format, default: %d.%m.%y %T" },
        Opt { long: "digest"     , short: "g", arg: 1, descr: "digest for signature creation, default: key-specific" },
        Opt { long: "rsa-padding", short: "R", arg: 1, descr: "padding for RSA signatures, default: pkcs1" },
        Opt { long: "outform"    , short: "f", arg: 1, descr: "encoding of generated cert, default: der" },
    ];
    Command::new(pki_acert, "z", "acert",
                "issue an attribute certificate", brief, options)
}
