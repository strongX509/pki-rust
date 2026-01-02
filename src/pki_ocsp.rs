use pki::Command;

pub fn pki_ocsp() -> i32 {
    println!("ocsp()");
    return 0;
}

inventory::submit! {
    Command::new(pki_ocsp, "o", "ocsp",
                "OCSP responder")
}
