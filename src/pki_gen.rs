use pki::Command;

pub fn pki_gen() -> i32 {
    println!("gen()");
    return 0;
}

inventory::submit! {
    Command::new(pki_gen, "g", "gen",
                "generate a new private key")
}
