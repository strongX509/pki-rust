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
// Create a self signed certificate.
//
pub fn pki_self() -> i32
{
    println!("self()");
    return 0;
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
        Opt { long: "san",             short: "a", arg: 1, descr: "subjectAltName to include in certificate" },
        Opt { long: "lifetime",        short: "l", arg: 1, descr: "days the certificate is valid, default: 1095" },
        Opt { long: "not-before",      short: "F", arg: 1, descr: "date/time the validity of the cert starts" },
        Opt { long: "not-after",       short: "T", arg: 1, descr: "date/time the validity of the cert ends" },
        Opt { long: "dateform",        short: "D", arg: 1, descr: "strptime(3) input format, default: %d.%m.%y %T" },
        Opt { long: "serial",          short: "s", arg: 1, descr: "serial number in hex, default: random" },
        Opt { long: "ca",              short: "b", arg: 0, descr: "include CA basicConstraint, default: no" },
        Opt { long: "pathlen",         short: "p", arg: 1, descr: "set path length constraint" },
        Opt { long: "addrblock",       short: "B", arg: 1, descr: "RFC 3779 addrBlock to include" },
        Opt { long: "nc-permitted",    short: "n", arg: 1, descr: "add permitted NameConstraint" },
        Opt { long: "nc-excluded",     short: "N", arg: 1, descr: "add excluded NameConstraint" },
        Opt { long: "cert-policy",     short: "P", arg: 1, descr: "certificatePolicy OID to include" },
        Opt { long: "cps-uri",         short: "C", arg: 1, descr: "Certification Practice statement URI for certificatePolicy" },
        Opt { long: "user-notice",     short: "U", arg: 1, descr: "user notice for certificatePolicy" },
        Opt { long: "policy-mapping",  short: "M", arg: 1, descr: "policyMapping from issuer to subject OID" },
        Opt { long: "policy-explicit", short: "E", arg: 1, descr: "requireExplicitPolicy constraint" },
        Opt { long: "policy-inhibit",  short: "H", arg: 1, descr: "inhibitPolicyMapping constraint" },
        Opt { long: "policy-any",      short: "A", arg: 1, descr: "inhibitAnyPolicy constraint" },
        Opt { long: "flag",            short: "e", arg: 1, descr: "include extendedKeyUsage flag" },
        Opt { long: "ocsp",            short: "o", arg: 1, descr: "OCSP AuthorityInfoAccess URI to include" },
        Opt { long: "digest",          short: "g", arg: 1, descr: "digest for signature creation, default: key-specific" },
        Opt { long: "rsa-padding",     short: "R", arg: 1, descr: "padding for RSA signatures, default: pkcs1" },
        Opt { long: "critical",        short: "X", arg: 1, descr: "critical extension OID to include for test purposes" },
        Opt { long: "outform",         short: "f", arg: 1, descr: "encoding of generated cert, default: der" },
    ];
    Command::new(pki_self, "s", "self",
                "create a self signed certificate", brief, options)
}
