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

use pki::Command;
use pki::Opt;

//
// Enroll an X.509 certificate with a SCEP server (RFC 8894).
//
pub fn pki_scep() -> i32
{
    println!("scep()");
    return 0;
}

//
// Register the command.
//
inventory::submit!
{
    let brief: &'static[&'static str] = &[
        "--url url [--in file] [--dn distinguished-name] [--san subjectAltName]+",
        " --cacert-enc file --cacert-sig file [--cacert file]+",
        "[--profile profile] [--password password]",
        "[--cert file --key file] [--cipher aes|des3]",
        "[--digest sha256|sha384|sha512|sha224|sha1] [--rsa-padding pkcs1|pss]",
        "[--interval time] [--maxpolltime time] [--outform der|pem]"
    ];
    let options: &'static[Opt] = &[
        Opt { long: "help",        short: "h", arg: 0, descr: "show usage information" },
        Opt { long: "url",         short: "u", arg: 1, descr: "URL of the SCEP server" },
        Opt { long: "in",          short: "i", arg: 1, descr: "RSA private key input file, default: stdin" },
        Opt { long: "dn",          short: "d", arg: 1, descr: "subject distinguished name (optional if --cert is given)" },
        Opt { long: "san",         short: "a", arg: 1, descr: "subjectAltName to include in cert request" },
        Opt { long: "profile",     short: "P", arg: 1, descr: "certificate profile name to include in cert request" },
        Opt { long: "password",    short: "p", arg: 1, descr: "challengePassword to include in cert request" },
        Opt { long: "cacert-enc",  short: "e", arg: 1, descr: "CA certificate for encryption" },
        Opt { long: "cacert-sig",  short: "s", arg: 1, descr: "CA certificate for signature verification" },
        Opt { long: "cacert",      short: "C", arg: 1, descr: "additional CA certificates" },
        Opt { long: "cert",        short: "c", arg: 1, descr: "old certificate about to be renewed" },
        Opt { long: "key",         short: "k", arg: 1, descr: "old RSA private key about to be replaced" },
        Opt { long: "cipher",      short: "E", arg: 1, descr: "encryption cipher, default: aes" },
        Opt { long: "digest",      short: "g", arg: 1, descr: "digest for signature creation, default: sha256" },
        Opt { long: "rsa-padding", short: "R", arg: 1, descr: "padding for RSA signatures, default: pkcs1" },
        Opt { long: "interval",    short: "t", arg: 1, descr: "poll interval, default: 60s" },
        Opt { long: "maxpolltime", short: "m", arg: 1, descr: "maximum poll time, default: 0 (no limit)" },
        Opt { long: "outform",     short: "f", arg: 1, descr: "encoding of stored certificates, default: der" },
    ];
    Command::new(pki_scep, "S", "scep",
                "enroll an X.509 certificate with a SCEP server", brief, options)
}
