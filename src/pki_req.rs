use pki::Command;

pub fn pki_req() -> i32 {
    println!("req()");
    return 0;
}

inventory::submit! {
    Command::new(pki_req, "r", "req",
                "create a PKCS#10 certificate request")
}
