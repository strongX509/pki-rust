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

use std::process::ExitCode;
use getopts::Matches;
use pki::{Command, Opt};

const DEFAULT_POLL_INTERVAL: u32 = 60; // seconds

//
// Enroll an X.509 certificate with an EST server (RFC 7030).
//
pub fn pki_est(matches: &Matches) -> ExitCode
{
    let url = match matches.opt_str("u") {
        Some(v) => { v }
        None => {
            println!("option '--url' is required");
            return ExitCode::from(2);
        }
    };
    println!("option: --url {}", url);

    let cacerts: Vec<String> = matches.opt_strs("C");
    for c in &cacerts {
         println!("option: --cacert {}", c);
    }
    if cacerts.len() == 0 {
        println!("option '--cacert' is required");
        return ExitCode::from(2);
    }

    let client_cert_file = match matches.opt_str("c") {
        Some(v) => { v }
        None => { "".to_string() }
    };
    println!("option: --cert {}", client_cert_file);

    let certid = match matches.opt_str("X") {
        Some(v) => { v }
        None => { "".to_string() }
    };
    println!("option: --certid {}", certid);

    let client_key_file = match matches.opt_str("k") {
        Some(v) => { v }
        None => { "".to_string() }
    };
    println!("option: --key {}", client_key_file);

    let keyid = match matches.opt_str("x") {
        Some(v) => { v }
        None => { "".to_string() }
    };
    println!("option: --keyid {}", keyid);

    if (!client_cert_file.is_empty() || !certid.is_empty()) &&
       (client_key_file.is_empty() && keyid.is_empty())
    {
        println!("'--key' or '--keyid' is required if '--cert' or '--certid' is set");
        return ExitCode::from(2);
    }

    if (!client_key_file.is_empty() || !keyid.is_empty()) &&
       (client_cert_file.is_empty() && certid.is_empty())
    {
        println!("'--cert' or '--certid' is required if '--key' or '--keyid' is set");
        return ExitCode::from(2);
    }

    if !client_key_file.is_empty() && !keyid.is_empty() {
        println!("options '--key' and '--keyid' can't be set both");
        return ExitCode::from(2);
    }

    if !client_cert_file.is_empty() && !certid.is_empty() {
        println!("options '--cert' and '--certid' can't be set both");
        return ExitCode::from(2);
    }

    if matches.opt_present("l") {
        let label = matches.opt_str("l").unwrap();
        println!("option: --label {}", label);
    }

    if matches.opt_present("i") {
        let file = matches.opt_str("i").unwrap();
        println!("option: --in {}", file);
    } else {
        println!("option '--in' missing: get input from stdin");
    }

    if matches.opt_present("p") {
        let user_pass = matches.opt_str("p").unwrap();
        println!("option: --userpass {}", user_pass);
    }

    let poll_interval: u32 = match matches.opt_str("t") {
        Some(string) => { string.parse().unwrap() }
        None => { DEFAULT_POLL_INTERVAL } // seconds
    };
    println!("option: --interval {} seconds", poll_interval);

    let max_poll_time: u32 = match matches.opt_str("m") {
        Some(string) => { string.parse().unwrap() }
        None => { 0 } // seconds
    };
    println!("option: --maxpolltime {} seconds", max_poll_time);

    if matches.opt_present("f") {
        let form = matches.opt_str("m").unwrap();
        println!("option: --outform {}", form);
    }

    println!("est()");
    return ExitCode::SUCCESS;
}

//
// Register the command.
//
inventory::submit!
{
    let brief: &'static[&'static str] = &[
        "--url url [--label label] [--in file] --cacert file+",
        "[--cert file|--certid hex --key file|--keyid hex]",
        "[--userpass username:password] [--interval time]",
        "[--maxpolltime time] [--outform der|pem]"
    ];
    let options: &'static[Opt] = &[
        Opt { long: "help",        short: "h", arg: 0, descr: "show usage information" },
        Opt { long: "url",         short: "u", arg: 1, descr: "URL of the EST server" },
        Opt { long: "label",       short: "l", arg: 1, descr: "label in the EST server path" },
        Opt { long: "in",          short: "i", arg: 1, descr: "PKCS#10 input file, default: stdin" },
        Opt { long: "cacert",      short: "C", arg: 2, descr: "CA certificate(s)" },
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
