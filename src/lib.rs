type Op = fn() -> i32;

pub struct Command {
	/// function implementing the command
	pub op: Op,
	/// short option character
	pub short: &'static str,
	/// long option string
	pub long: &'static str,
	/// description of the command
	pub description: &'static str,
	// usage summary of the command
	// char *line[MAX_LINES];
	// list of options the command accepts
	// command_option_t options[MAX_OPTIONS];
}

impl Command {
    pub const fn new(op: Op, short: &'static str, long: &'static str,
                     description: &'static str) -> Self {
        Command { op, short, long, description }
    }
}

inventory::collect!(Command);

