use pki::Command;

pub fn pki_dn() -> i32 {
    println!("dn()");
    return 0;
}

inventory::submit! {
    Command::new(pki_dn, "d", "dn",
                "extract the subject DN of an X.509 certificate")
}
