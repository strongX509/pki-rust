use pki::Command;

pub fn pki_scepca() -> i32 {
    println!("scepca()");
    return 0;
}

inventory::submit! {
    Command::new(pki_scepca, "C", "scepca",
                "get CA [and RA] certificate[s] from a SCEP server")
}
