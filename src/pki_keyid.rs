use pki::Command;

pub fn pki_keyid() -> i32 {
    println!("keyid()");
    return 0;
}

inventory::submit! {
    Command::new(pki_keyid, "k", "keyid",
                "calculate key identifiers of a key/certificate")
}
