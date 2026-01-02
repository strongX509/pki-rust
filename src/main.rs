// Copyright 2026 Andreas Steffen
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

use std::env;
use std::process::ExitCode;
use getopts::Options;
use pki::Command;

pub mod pki_acert;
pub mod pki_dn;
pub mod pki_est;
pub mod pki_estca;
pub mod pki_gen;
pub mod pki_issue;
pub mod pki_keyid;
pub mod pki_ocsp;
pub mod pki_pkcs12;
pub mod pki_pkcs7;
pub mod pki_print;
pub mod pki_pub;
pub mod pki_req;
pub mod pki_scep;
pub mod pki_scepca;
pub mod pki_self;
pub mod pki_signcrl;
pub mod pki_verify;

fn usage()
{
    println!("usage:");
    println!("  pki command [options]");
    println!("commands:");
    for cmd in inventory::iter::<Command> {
        println!("  --{:7} (-{})  {}", cmd.long, cmd.short, cmd.description);
    }
}

/// command parsing and execution

fn main() -> ExitCode {
    // add all pki main command options
    let mut opts = Options::new();
    opts.optflag("h", "help", "show usage information");
    for cmd in inventory::iter::<Command> {
        opts.optflag(cmd.short, cmd.long, cmd.description);
    }

    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        println!("command missing");
        usage();
        return ExitCode::FAILURE;
    }

    let matches = match opts.parse(&args[1..]) {
        Ok(m)  => { m }
        Err(f) => {
            println!("{}", f.to_string());
            usage();
            return  ExitCode::FAILURE;
        }
    };

    if matches.opt_present("h") {
        usage();
        return ExitCode::SUCCESS;
    }

    for cmd in inventory::iter::<Command> {
        if matches.opt_present(cmd.short) {
            (cmd.op)();
            break;
        }
    }

    return ExitCode::SUCCESS;
}
