pub mod x509;

#[derive(Debug)]
/// kind of certificate
pub enum CertType {
    /// just any certificate
    ANY,
    /// X.509 certificate
    X509,
    /// X.509 certificate revocation list
    X509Crl,
    /// X.509 online certificate status protocol request
    X509OcspRequest,
	/// X.509 online certificate status protocol response
    X509OcspResponse,
	/// X.509 attribute certificate
    X509Ac,
	/// trusted, preinstalled public key
    TrustedPubkey,
	/// PKCS#10 certificate request
    PKCS10Request,
	/// PGP certificate
    GPG,
}
