// Copyright 2026 Andreas Steffen
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

//
// Print overview of the top level pki commands
//
fn usage()
{
    println!("usage:");
    println!("  pki command [options]");
    println!("commands:");
    println!("  --{:7} (-{})  {}", "help", "h", "show usage information");
    for cmd in inventory::iter::<Command> {
        println!("  --{:7} (-{})  {}", cmd.long, cmd.short, cmd.descr);
    }
}

//
// Print usage text for a particular pki command
//
fn cmd_usage(cmd: &Command)
{
    println!("usage:");
    print!("  pki --{} ", cmd.long);
    let mut first = true;
    for line in cmd.brief {
       if first {
          first = false;
        } else {
           print!("{:5}", " ");
       }
       println!("{}", line);
    }
    println!("options:");
   for option in cmd.options {
        println!("  --{:15} (-{})  {}", option.long, option.short, option.descr);
    }
}

//
// Parse command line options and execute selected pki command
//
fn main() -> ExitCode
{
    // add all pki main command options
    let mut opts = Options::new();
    opts.optflag("h", "help", "show usage information");
    for cmd in inventory::iter::<Command> {
        opts.optflag(cmd.short, cmd.long, cmd.descr);
    }

    // get command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        println!("command missing");
        usage();
        return ExitCode::FAILURE;
    }

    // parse first command line argument only
    let command_arg = vec![ args[1].clone() ];
    let matches = match opts.parse(&command_arg) {
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
        if matches.opt_present(cmd.short)
        {
            // add all options for specific pki command
            let mut cmd_opts = Options::new();
            for option in cmd.options {
                if option.arg == 0 {
                    cmd_opts.optflag(option.short, option.long, option.descr);
                } else {
                    cmd_opts.optopt(option.short, option.long, option.descr, "");
                }
            }

            // parse command line arguments for specific pki command
            let cmd_matches = match cmd_opts.parse(&args[2..]) {
                Ok(m)  => { m }
                Err(f) => {
                    println!("{}", f.to_string());
                    cmd_usage(cmd);
                    return  ExitCode::FAILURE;
                }
            };

            if cmd_matches.opt_present("h") {
                cmd_usage(cmd);
            } else {
               (cmd.op)();
            }
            break;
        }
    }

   return ExitCode::SUCCESS;
}
