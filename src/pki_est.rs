use pki::Command;

pub fn pki_est() -> i32 {
    println!("est()");
    return 0;
}

inventory::submit! {
    Command::new(pki_est, "E", "est",
                "enroll an X.509 certificate with an EST server")
}
