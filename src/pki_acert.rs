use pki::Command;

pub fn pki_acert() -> i32 {
    println!("acert()");
    return 0;
}

inventory::submit! {
    Command::new(pki_acert, "z", "acert",
                "issue an attribute certificate")
}
