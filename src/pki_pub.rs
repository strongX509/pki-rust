use pki::Command;

pub fn pki_pub() -> i32 {
    println!("pub()");
    return 0;
}

inventory::submit! {
    Command::new(pki_pub, "p", "pub",
                "extract the public key from a private key/certificate")
}
