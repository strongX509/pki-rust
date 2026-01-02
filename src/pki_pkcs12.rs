use pki::Command;

pub fn pki_pkcs12() -> i32 {
    println!("pkcs12()");
    return 0;
}

inventory::submit! {
    Command::new(pki_pkcs12, "u", "pkcs12",
                "PKCS#12 functions")
}
