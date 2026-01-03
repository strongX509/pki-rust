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

use pki::Command;
use pki::Opt;

//
// Enroll an X.509 certificate with an EST server (RFC 7030).
//
pub fn pki_est() -> i32
{
    println!("est()");
    return 0;
}

//
// Register the command.
//
inventory::submit!
{
    let brief: &'static[&'static str] = &[
        "--url url [--label label] [--in file] --cacert file",
        "[--cert file|--certid hex --key file|--keyid hex]",
        "[--userpass username:password] [--interval time]",
        "[--maxpolltime time] [--outform der|pem]"
    ];
    let options: &'static[Opt] = &[
        Opt { long: "help",        short: "h", arg: 0, descr: "show usage information" },
        Opt { long: "url",         short: "u", arg: 1, descr: "URL of the EST server" },
        Opt { long: "label",       short: "l", arg: 1, descr: "label in the EST server path" },
        Opt { long: "in",          short: "i", arg: 1, descr: "PKCS#10 input file, default: stdin" },
        Opt { long: "cacert",      short: "C", arg: 1, descr: "CA certificate(s)" },
        Opt { long: "cert",        short: "c", arg: 1, descr: "old certificate about to be renewed" },
        Opt { long: "certid",      short: "X", arg: 1, descr: "smartcard or TPM certificate object handle"  },
        Opt { long: "key",         short: "k", arg: 1, descr: "old private key about to be replaced" },
        Opt { long: "keyid",       short: "x", arg: 1, descr: "smartcard or TPM private key object handle" },
        Opt { long: "userpass",    short: "p", arg: 1, descr: "username:password for http basic auth" },
        Opt { long: "interval",    short: "t", arg: 1, descr: "poll interval, default: 60s" },
        Opt { long: "maxpolltime", short: "m", arg: 1, descr: "maximum poll time, default: 0 (no limit)" },
        Opt { long: "outform",     short: "f", arg: 1, descr: "encoding of stored certificates, default: der" },
    ];
   Command::new(pki_est, "E", "est",
                "enroll an X.509 certificate with an EST server", brief, options)
}
