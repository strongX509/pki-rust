use pki::Command;

pub fn pki_issue() -> i32 {
    println!("issue()");
    return 0;
}

inventory::submit! {
    Command::new(pki_issue, "i", "issue",
                "issue an attribute certificate")
}
