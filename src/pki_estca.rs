use pki::Command;

pub fn pki_estca() -> i32 {
    println!("estca()");
    return 0;
}

inventory::submit! {
    Command::new(pki_estca, "e", "estca",
                "get CA certificate[s] from an EST server")
}
