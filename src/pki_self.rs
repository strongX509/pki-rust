use pki::Command;

pub fn pki_self() -> i32 {
    println!("self()");
    return 0;
}

inventory::submit! {
    Command::new(pki_self, "s", "self",
                "create a self signed certificate")
}
