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

use std::process::ExitCode;
use getopts::Matches;
use pki::Command;
use pki::Opt;

//
// Enroll an X.509 certificate with a SCEP server (RFC 8894).
//
pub fn pki_scep(matches: &Matches) -> ExitCode
{
    if matches.opt_present("u") {
        let url = matches.opt_str("u").unwrap();
        println!("option: --url {}", url);
    } else {
        println!("option '--url' is required");
        return ExitCode::from(2);
    }

    if matches.opt_present("i") {
        let file = matches.opt_str("i").unwrap();
        println!("option: --in {}", file);
    } else {
        println!("option '--in' missing: get input from stdin");
    }

    if matches.opt_present("d") {
        let dn = matches.opt_str("d").unwrap();
        println!("option: --dn {}", dn);
    }

    let san: Vec<String> = matches.opt_strs("a");
    for s in &san
    {
        println!("option: --san {}", s);
    }

    if matches.opt_present("e") {
        let cacert_enc = matches.opt_str("e").unwrap();
        println!("option: --cacert-enc {}", cacert_enc);
    }

    if matches.opt_present("s") {
        let cacert_sig = matches.opt_str("s").unwrap();
        println!("option: --cacert-sig {}", cacert_sig);
    }

    let cacerts: Vec<String> = matches.opt_strs("c");
    for c in &cacerts {
         println!("option: --cacert {}", c);
    }

    if matches.opt_present("P") {
        let profile = matches.opt_str("P").unwrap();
        println!("option: --profile {}", profile);
    }

    if matches.opt_present("p") {
        let password = matches.opt_str("p").unwrap();
        println!("option: --password {}", password);
    }

    let cert = match matches.opt_str("c") {
        Some(v) => { v }
        None => { "".to_string() }
    };
    println!("option: --cert {}", cert);

    let key = match matches.opt_str("k") {
        Some(v) => { v }
        None => { "".to_string() }
    };
    println!("option: --key {}", key);

    if !cert.is_empty() && key.is_empty()
    {
        println!("option '--key' is required if '--cert' is set");
        return ExitCode::from(2);
    }

    if !key.is_empty() && cert.is_empty()
    {
        println!("option '--cert' is required if '--key' is set");
        return ExitCode::from(2);
    }

    if matches.opt_present("E") {
        let cipher = matches.opt_str("E").unwrap();
        println!("option: --cipher {}", cipher);
    }

    if matches.opt_present("g") {
        let digest = matches.opt_str("g").unwrap();
        println!("option: --digest {}", digest);
    }

    if matches.opt_present("R") {
        let padding = matches.opt_str("R").unwrap();
        println!("option: --rsa-padding {}", padding);
    }

    if matches.opt_present("t") {
        let interval = matches.opt_str("t").unwrap();
        println!("option: --interval {}", interval);
    }

    if matches.opt_present("m") {
        let max_poll_time = matches.opt_str("m").unwrap();
        println!("option: --maxpolltime {}", max_poll_time);
    }

    if matches.opt_present("f") {
        let form = matches.opt_str("f").unwrap();
        println!("option: --outform {}", form);
    }

    println!("scep()");
    return ExitCode::SUCCESS;
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
        Opt { long: "san",         short: "a", arg: 2, descr: "subjectAltName to include in cert request" },
        Opt { long: "profile",     short: "P", arg: 1, descr: "certificate profile name to include in cert request" },
        Opt { long: "password",    short: "p", arg: 1, descr: "challengePassword to include in cert request" },
        Opt { long: "cacert-enc",  short: "e", arg: 1, descr: "CA certificate for encryption" },
        Opt { long: "cacert-sig",  short: "s", arg: 1, descr: "CA certificate for signature verification" },
        Opt { long: "cacert",      short: "C", arg: 2, descr: "additional CA certificates" },
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
