use pki::Command;

pub fn pki_verify() -> i32 {
    println!("verify()");
    return 0;
}

inventory::submit! {
    Command::new(pki_verify, "v", "verify",
                "verify a certificate using one or more CA certificates")
}
