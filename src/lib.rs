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

use std::process::ExitCode;
use getopts::Matches;

pub mod strongswan;

type Op = fn(&Matches) -> ExitCode;

pub struct Opt {
	/// long option string
	pub long: &'static str,
	/// short option character
	pub short: &'static str,
	/// expected argument to option, no/req/multi argument
	pub arg: u32,
	/// description of the option
	pub descr: &'static str,
}

pub struct Command {
	/// function implementing the command
	pub op: Op,
	/// short option character
	pub short: &'static str,
	/// long option string
	pub long: &'static str,
	/// description of the command
	pub descr: &'static str,
	/// usage summary of the command
	pub brief: &'static[&'static str],
	// list of options the command accepts
	pub options: &'static[Opt]
}

impl Command {
    pub const fn new(op: Op, short: &'static str, long: &'static str,
                     descr: &'static str, brief: &'static[&'static str],
                     options: &'static[Opt]) -> Self
    {
        Command { op, short, long, descr, brief, options }
    }
}

inventory::collect!(Command);

