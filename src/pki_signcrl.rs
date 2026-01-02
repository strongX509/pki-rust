use pki::Command;

pub fn pki_signcrl() -> i32 {
    println!("signcrl()");
    return 0;
}

inventory::submit! {
    Command::new(pki_signcrl, "c", "signcrl",
                "issue a CRL using a CA certificate and key")
}
