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

use std::process::ExitCode;
use getopts::Matches;
use pki::Command;
use pki::Opt;

//
// Create a self signed certificate.
//
pub fn pki_self(matches: &Matches) -> ExitCode
{
   let file = match matches.opt_str("i") {
        Some(v) => { v }
        None => { "".to_string() }
    };
    println!("option: --in {}", file);

    let keyid = match matches.opt_str("x") {
        Some(v) => { v }
        None => { "".to_string() }
    };
    println!("option: --keyid {}", keyid);

    if !file.is_empty() && !keyid.is_empty() {
        println!("options '--in' and '--keyid' can't be set both");
        return ExitCode::SUCCESS;
    }

    if file.is_empty() && keyid.is_empty() {
        println!("option '--in' or '--keyid' missing: get input from stdin");
    }

    if matches.opt_present("t") {
        let in_type = matches.opt_str("t").unwrap();
        println!("option: --type {}", in_type);
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

    if matches.opt_present("l") {
        let lifetime = matches.opt_str("l").unwrap();
        println!("option: --lifetime {}", lifetime);
    }

    if matches.opt_present("s") {
        let serial = matches.opt_str("s").unwrap();
        println!("option: --serial {}", serial);
    }

    let ca: bool = matches.opt_present("b");
    println!("ca flag:  {}", ca);

    if matches.opt_present("p") {
        let pathlen = matches.opt_str("p").unwrap();
        println!("option: --pathlen {}", pathlen);
    }

    if matches.opt_present("F") {
        let datenb = matches.opt_str("F").unwrap();
        println!("option: --not-before {}", datenb);
    }

    if matches.opt_present("T") {
        let datena = matches.opt_str("T").unwrap();
        println!("option: --not-after {}", datena);
    }

    if matches.opt_present("D") {
        let dateform = matches.opt_str("D").unwrap();
        println!("option: --dateform {}", dateform);
    }

    let flags: Vec<String> = matches.opt_strs("e");
    for f in &flags
     {
            println!("option: --flag {}", f);
    }

    let ocsp_uris: Vec<String> = matches.opt_strs("o");
    for u in &ocsp_uris
    {
        println!("option: --ocsp {}", u);
    }

    let addrblocks: Vec<String> = matches.opt_strs("B");
    for b in &addrblocks
    {
         println!("option: --addrblock {}", b);
    }

    let permitted: Vec<String> = matches.opt_strs("n");
    for nc in &permitted
    {
        println!("option: --nc-permitted {}", nc);
    }

    let excluded: Vec<String> = matches.opt_strs("N");
    for nc in &excluded
    {
        println!("option: --nc-excluded {}", nc);
    }

    let mappings: Vec<String> = matches.opt_strs("M");
    for m in &mappings
    {
        println!("option: --policy-mapping {}", m);
    }

    if matches.opt_present("E") {
        let require_explicit = matches.opt_str("E").unwrap();
        println!("option: --policy-explicit {}", require_explicit);
    }

    if matches.opt_present("H") {
        let inhibit_mapping = matches.opt_str("H").unwrap();
        println!("option: --policy-inhibit {}", inhibit_mapping);
    }

    if matches.opt_present("A") {
        let inhibit_any = matches.opt_str("A").unwrap();
        println!("option: --policy-any {}", inhibit_any);
    }

    let policies: Vec<String> = matches.opt_strs("P");
    for p in &policies
    {
        println!("option: --cert-policy {}", p);
    }

    let cps_uri: Vec<String> = matches.opt_strs("C");
    for u in &cps_uri
    {
        println!("option: --cps-uri {}", u);
    }

    let user_notice: Vec<String> = matches.opt_strs("U");
    for n in &user_notice
    {
        println!("option: --user-notice {}", n);
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

    println!("self()");
    return ExitCode::SUCCESS;
}

//
// Register the command.
//
inventory::submit!
{
    let brief: &'static[&'static str] = &[
        "[--in file|--keyid hex] [--type rsa|ecdsa|ed25519|ed448|priv]",
        " --dn distinguished-name [--san subjectAltName]+",
        "[--lifetime days] [--serial hex] [--ca] [--ocsp uri]+",
        "[--not-before datetime] [--not-after datetime] [--dateform form]",
        "[--flag serverAuth|clientAuth|crlSign|ocspSigning|msSmartcardLogon]+",
        "[--nc-permitted name] [--nc-excluded name]",
        "[--policy-map issuer-oid:subject-oid]",
        "[--policy-explicit len] [--policy-inhibit len] [--policy-any len]",
        "[--cert-policy oid [--cps-uri uri] [--user-notice text]]+",
        "[--digest md5|sha1|sha224|sha256|sha384|sha512|sha3_224|sha3_256|sha3_384|sha3_512]",
        "[--rsa-padding pkcs1|pss] [--critical oid]",
        "[--outform der|pem]"
    ];
    let options: &'static[Opt] = &[
        Opt { long: "help",            short: "h", arg: 0, descr: "show usage information" },
        Opt { long: "in",              short: "i", arg: 1, descr: "private key input file, default: stdin" },
        Opt { long: "keyid",           short: "x", arg: 1, descr: "smartcard or TPM private key object handle" },
        Opt { long: "type",            short: "t", arg: 1, descr: "type of input key, default: priv" },
        Opt { long: "dn",              short: "d", arg: 1, descr: "subject and issuer distinguished name" },
        Opt { long: "san",             short: "a", arg: 2, descr: "subjectAltName to include in certificate" },
        Opt { long: "lifetime",        short: "l", arg: 1, descr: "days the certificate is valid, default: 1095" },
        Opt { long: "not-before",      short: "F", arg: 1, descr: "date/time the validity of the cert starts" },
        Opt { long: "not-after",       short: "T", arg: 1, descr: "date/time the validity of the cert ends" },
        Opt { long: "dateform",        short: "D", arg: 1, descr: "strptime(3) input format, default: %d.%m.%y %T" },
        Opt { long: "serial",          short: "s", arg: 1, descr: "serial number in hex, default: random" },
        Opt { long: "ca",              short: "b", arg: 0, descr: "include CA basicConstraint, default: no" },
        Opt { long: "pathlen",         short: "p", arg: 1, descr: "set path length constraint" },
        Opt { long: "addrblock",       short: "B", arg: 2, descr: "RFC 3779 addrBlock to include" },
        Opt { long: "nc-permitted",    short: "n", arg: 2, descr: "add permitted NameConstraint" },
        Opt { long: "nc-excluded",     short: "N", arg: 2, descr: "add excluded NameConstraint" },
        Opt { long: "cert-policy",     short: "P", arg: 2, descr: "certificatePolicy OID to include" },
        Opt { long: "cps-uri",         short: "C", arg: 2, descr: "Certification Practice statement URI for certificatePolicy" },
        Opt { long: "user-notice",     short: "U", arg: 2, descr: "user notice for certificatePolicy" },
        Opt { long: "policy-mapping",  short: "M", arg: 2, descr: "policyMapping from issuer to subject OID" },
        Opt { long: "policy-explicit", short: "E", arg: 1, descr: "requireExplicitPolicy constraint" },
        Opt { long: "policy-inhibit",  short: "H", arg: 1, descr: "inhibitPolicyMapping constraint" },
        Opt { long: "policy-any",      short: "A", arg: 1, descr: "inhibitAnyPolicy constraint" },
        Opt { long: "flag",            short: "e", arg: 2, descr: "include extendedKeyUsage flag" },
        Opt { long: "ocsp",            short: "o", arg: 2, descr: "OCSP AuthorityInfoAccess URI to include" },
        Opt { long: "digest",          short: "g", arg: 1, descr: "digest for signature creation, default: key-specific" },
        Opt { long: "rsa-padding",     short: "R", arg: 1, descr: "padding for RSA signatures, default: pkcs1" },
        Opt { long: "critical",        short: "X", arg: 1, descr: "critical extension OID to include for test purposes" },
        Opt { long: "outform",         short: "f", arg: 1, descr: "encoding of generated cert, default: der" },
    ];
    Command::new(pki_self, "s", "self",
                "create a self signed certificate", brief, options)
}
