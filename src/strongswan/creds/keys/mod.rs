#[derive(Debug)]
/// type of a key pair, the used crypto system
pub enum KeyType {
    /// key type wildcard
    ANY    = 0,
    /// RSA crypto system as in PKCS#1
    RSA     = 1,
    /// ECDSA as in ANSI X9.62
    ECDSA   = 2,
    /// DSA
    DSA     = 3,
    /// Ed25519 PureEdDSA instance as in RFC 8032
    ED25519 = 4,
    /// Ed448   PureEdDSA instance as in RFC 8032
    ED448   = 5,
}
