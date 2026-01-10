// Copyright 2015-2026 Andreas Steffen
//
// Copyright 2009 Martin Willi
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
use pki::X509_NO_CONSTRAINT;

//
// Issue a certificate using a CA certificate and key.
//
pub fn pki_issue(matches: &Matches) -> ExitCode
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

   if matches.opt_present("i") {
        let file = matches.opt_str("i").unwrap();
        println!("option: --in {}", file);
    } else {
        println!("option '--in' missing: get input from stdin");
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

    let lifetime: i64 = 24 * 60 * 60 * match matches.opt_str("l") {
        Some(string) => { string.parse().unwrap() }
        None => { 1095 } // days
    };
    println!("option: --lifetime {} seconds", lifetime);

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

    if matches.opt_present("s") {
        let serial = matches.opt_str("s").unwrap();
        println!("option: --serial {}", serial);
    }

    let ca: bool = matches.opt_present("b");
    println!("ca flag:  {}", ca);

    let pathlen: u32 = match matches.opt_str("p") {
        Some(string) => { string.parse().unwrap() }
        None => { X509_NO_CONSTRAINT }
    };
    println!("option: --pathlen {}", pathlen);

    let flags: Vec<String> = matches.opt_strs("e");
    for f in &flags
     {
            println!("option: --flag {}", f);
    }

    let crl_uris: Vec<String> = matches.opt_strs("u");
    for u in &crl_uris
    {
        println!("option: --crl {}", u);
    }

    let crl_issuers: Vec<String> = matches.opt_strs("I");
    for i in &crl_issuers
    {
        println!("option: --crlissuer {}", i);
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

    let require_explicit: u32 = match matches.opt_str("E") {
        Some(string) => { string.parse().unwrap() }
        None => { X509_NO_CONSTRAINT }
     };
    println!("option: --policy-explicit {}", require_explicit);

    let inhibit_mapping: u32 = match matches.opt_str("H") {
        Some(string) => { string.parse().unwrap() }
        None => { X509_NO_CONSTRAINT }
     };
    println!("option: --policy-inhibit {}", inhibit_mapping);

    let inhibit_any: u32 = match matches.opt_str("A") {
        Some(string) => { string.parse().unwrap() }
        None => { X509_NO_CONSTRAINT }
     };
    println!("option: --policy-any {}", inhibit_any);

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

    println!("issue()");
    return ExitCode::SUCCESS;
}

//
// Register the command.
//
inventory::submit!
{
    let brief: &'static[&'static str] = &[
        "[--in file] [--type pub|pkcs10|priv|rsa|ecdsa|ed25519|ed448]",
        " --cakey file|--cakeyid hex --cacert file [--dn subject-dn]",
        "[--san subjectAltName]+ [--lifetime days] [--serial hex]",
        "[--not-before datetime] [--not-after datetime] [--dateform form]",
        "[--ca] [--pathlen len] [--addrblock block]+",
        "[--flag serverAuth|clientAuth|crlSign|ocspSigning|msSmartcardLogon]+",
        "[--crl uri [--crlissuer i]]+ [--ocsp uri]+ [--nc-permitted name]+",
        "[--nc-excluded name]+ [--policy-mapping issuer-oid:subject-oid]+",
        "[--policy-explicit len] [--policy-inhibit len] [--policy-any len]",
        "[--cert-policy oid [--cps-uri uri] [--user-notice text]]+",
        "[--digest md5|sha1|sha224|sha256|sha384|sha512|sha3_224|sha3_256|sha3_384|sha3_512]",
        "[--rsa-padding pkcs1|pss] [--critical oid]",
        "[--outform der|pem]"
    ];
    let options: &'static[Opt] = &[
        Opt { long: "help",            short: "h", arg: 0, descr: "show usage information" },
        Opt { long: "in",              short: "i", arg: 1, descr: "key/request file to issue, default: stdin" },
        Opt { long: "type",            short: "t", arg: 1, descr: "type of input, default: pub" },
        Opt { long: "cacert",          short: "c", arg: 1, descr: "CA certificate file" },
        Opt { long: "cakey",           short: "k", arg: 1, descr: "CA private key file" },
        Opt { long: "cakeyid",         short: "x", arg: 1, descr: "smartcard or TPM CA private key object handle" },
        Opt { long: "dn",              short: "d", arg: 1, descr: "distinguished name to include as subject" },
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
        Opt { long: "crl",             short: "u", arg: 2, descr: "CRL distribution point URI to include" },
        Opt { long: "crlissuer",       short: "I", arg: 2, descr: "CRL Issuer for CRL at distribution point" },
        Opt { long: "ocsp",            short: "o", arg: 2, descr: "OCSP AuthorityInfoAccess URI to include" },
        Opt { long: "digest",          short: "g", arg: 1, descr: "digest for signature creation, default: key-specific" },
        Opt { long: "rsa-padding",     short: "R", arg: 1, descr: "padding for RSA signatures, default: pkcs1" },
        Opt { long: "critical",        short: "X", arg: 1, descr: "critical extension OID to include" },
        Opt { long: "outform",         short: "f", arg: 1, descr: "encoding of generated cert, default: der" },
    ];
    Command::new(pki_issue, "i", "issue",
                "issue an attribute certificate", brief, options)
}
