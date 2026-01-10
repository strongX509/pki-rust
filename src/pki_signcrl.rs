// Copyright 2017-2026 Andreas Steffen
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

use std::process::ExitCode;
use getopts::Matches;
use pki::{Command, Opt};

//
// Sign a CRL.
//
pub fn pki_signcrl(matches: &Matches) -> ExitCode
{
  let cacert = match matches.opt_str("c") {
        Some(v) => { v }
        None => {
            println!("option '--cacert' is required");
            return ExitCode::from(2);
        }
    };
    println!("option: --cacert {}", cacert);

    let cakey = match matches.opt_str("k") {
        Some(v) => { v }
        None => { "".to_string() }
    };
    println!("option: --cakey {}", cakey);

    let cakeyid = match matches.opt_str("x") {
        Some(v) => { v }
        None => { "".to_string() }
    };
    println!("option: --cakeyid {}", cakeyid);

    if cakey.is_empty() && cakeyid.is_empty() {
       println!("option '--cakey' or '--cakeyid' is required");
        return ExitCode::from(2);
    }

    if !cakey.is_empty() && !cakeyid.is_empty() {
        println!("options '--cakey' and '--cakeyid' can't be set both");
        return ExitCode::from(2);
    }

    let lifetime: i64 = 24 * 60 * 60 * match matches.opt_str("l") {
        Some(string) => { string.parse().unwrap() }
        None => { 15 } // days
    };
    println!("option: --lifetime {} seconds", lifetime);

    if matches.opt_present("F") {
        let datetu = matches.opt_str("F").unwrap();
        println!("option: --this-update {}", datetu);
    }

    if matches.opt_present("T") {
        let datenu = matches.opt_str("T").unwrap();
        println!("option: --next-update {}", datenu);
    }

    if matches.opt_present("D") {
        let dateform = matches.opt_str("D").unwrap();
        println!("option: --dateform {}", dateform);
    }

    if matches.opt_present("a") {
        let last_crl = matches.opt_str("a").unwrap();
        println!("option: --lastcrl {}", last_crl);
    }

    if matches.opt_present("b") {
        let base_crl = matches.opt_str("b").unwrap();
        println!("option: --basecrl {}", base_crl);
    }

    let crl_uris: Vec<String> = matches.opt_strs("u");
    for u in &crl_uris
    {
        println!("option: --crl {}", u);
    }

    let certs: Vec<String> = matches.opt_strs("z");
    for c in &certs
    {
        println!("option: --cert {}", c);
    }

    let serial: Vec<String> = matches.opt_strs("s");
    for s in &serial
    {
        println!("option: --serlal {}", s);
    }

    let reason: Vec<String> = matches.opt_strs("r");
    for r in &reason
    {
        println!("option: --reason {}", r);
    }

    let date: Vec<String> = matches.opt_strs("d");
    for d in &date
    {
        println!("option: --date {}", d);
    }

    if matches.opt_present("X") {
        let critical_extension_oid = matches.opt_str("X").unwrap();
        println!("option: --critical {}", critical_extension_oid);
    }

    if matches.opt_present("g") {
        let digest = matches.opt_str("g").unwrap();
        println!("option: --digest {}", digest);
    }

    if matches.opt_present("R") {
        let padding = matches.opt_str("R").unwrap();
        println!("option: --rsa-padding {}", padding);
    }

    if matches.opt_present("f") {
        let form = matches.opt_str("f").unwrap();
        println!("option: --outform {}", form);
    }

    println!("signcrl()");
    return ExitCode::SUCCESS;
}

//
// Register the command.
//
inventory::submit!
{
    let brief: &'static[&'static str] = &[
        "--cacert file --cakey file|--cakeyid hex [--lifetime days]",
        "[--this-update datetime] [--next-update datetime] [--dateform form]",
        "[--lastcrl crl] [--basecrl crl] [--crluri uri]+",
        "[[--reason key-compromise|ca-compromise|affiliation-changed|",
        "           superseded|cessation-of-operation|certificate-hold]",
        " [--date timestamp] --cert file|--serial hex]*",
        "[--digest md5|sha1|sha224|sha256|sha384|sha512|sha3_224|sha3_256|sha3_384|sha3_512]",
        "[--rsa-padding pkcs1|pss] [--critical oid] [--outform der|pem]"
    ];
    let options: &'static[Opt] = &[
        Opt { long: "help",        short: "h", arg: 0, descr: "show usage information" },
        Opt { long: "cacert",      short: "c", arg: 1, descr: "CA certificate file" },
        Opt { long: "cakey",       short: "k", arg: 1, descr: "CA private key file" },
        Opt { long: "cakeyid",     short: "x", arg: 1, descr: "smartcard or TPM CA private key object handle" },
        Opt { long: "lifetime",    short: "l", arg: 1, descr: "days the CRL gets a nextUpdate, default: 15" },
        Opt { long: "this-update", short: "F", arg: 1, descr: "date/time the validity of the CRL starts" },
        Opt { long: "next-update", short: "T", arg: 1, descr: "date/time the validity of the CRL ends" },
        Opt { long: "dateform",    short: "D", arg: 1, descr: "strptime(3) input format, default: %d.%m.%y %T" },
        Opt { long: "lastcrl",     short: "a", arg: 1, descr: "CRL of lastUpdate to copy revocations from" },
        Opt { long: "basecrl",     short: "b", arg: 1, descr: "base CRL to create a delta CRL for" },
        Opt { long: "crluri",      short: "u", arg: 2, descr: "freshest delta CRL URI to include" },
        Opt { long: "cert",        short: "z", arg: 2, descr: "certificate file to revoke" },
        Opt { long: "serial",      short: "s", arg: 2, descr: "hex encoded certificate serial number to revoke" },
        Opt { long: "reason",      short: "r", arg: 2, descr: "reason for certificate revocation" },
        Opt { long: "date",        short: "d", arg: 2, descr: "revocation date as unix timestamp, default: now" },
        Opt { long: "digest",      short: "g", arg: 1, descr: "digest for signature creation, default: key-specific" },
        Opt { long: "rsa-padding", short: "R", arg: 1, descr: "padding for RSA signatures, default: pkcs1" },
        Opt { long: "critical",    short: "X", arg: 1, descr: "critical extension OID to include for test purposes" },
        Opt { long: "outform",     short: "f", arg: 1, descr: "encoding of generated crl, default: der" },
    ];
    Command::new(pki_signcrl, "c", "signcrl",
                "issue a CRL using a CA certificate and key", brief, options)
}