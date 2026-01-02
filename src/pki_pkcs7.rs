use pki::Command;

pub fn pki_pkcs7() -> i32 {
    println!("pkcs7()");
    return 0;
}

inventory::submit! {
    Command::new(pki_pkcs7, "7", "pkcs7",
                "PKCS#7 wrap/unwrap functions")
}
