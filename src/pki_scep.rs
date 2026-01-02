use pki::Command;

pub fn pki_scep() -> i32 {
    println!("scep()");
    return 0;
}

inventory::submit! {
    Command::new(pki_scep, "S", "scep",
                "enroll an X.509 certificate with a SCEP server")
}
