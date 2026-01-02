use pki::Command;

pub fn pki_print() -> i32 {
    println!("print()");
    return 0;
}

inventory::submit! {
    Command::new(pki_print, "a", "print",
                "print a credential in a human readable form")
}
