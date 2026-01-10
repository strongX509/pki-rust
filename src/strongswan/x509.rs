use bitflags::bitflags;

pub const X509_NO_CONSTRAINT: u32 = 255;

bitflags! {
    /// X.509 certificate flags
    pub struct X509Flag: u32 {
        /// cert has no constraints
        const NONE =               0b00000000000;
        /// cert has CA constraint
        const CA =                 0b00000000001;
        /// cert has AA constraint
        const AA =                 0b00000000010;
        /// cert has OCSP signer constraint
        const OCSP_SIGNER =        0b00000000100;
        /// cert has serverAuth key usage
        const SERVER_AUTH =        0b00000001000;
        /// cert has clientAuth key usage
        const CLIENT_AUTH =        0b00000010000;
        /// cert is self-signed
        const SELF_SIGNED =        0b00000100000;
        /// cert has an ipAddrBlocks extension
        const IP_ADDR_BLOCKS =     0b00001000000;
        /// cert has CRL sign key usage
        const CRL_SIGN =           0b00010000000;
        /// cert has iKEIntermediate key usage
        const IKE_INTERMEDIATE =   0b00100000000;
        /// cert has Microsoft Smartcard Logon usage
        const MS_SMARTCARD_LOGON = 0b01000000000;
        /// cert either lacks keyUsage bits, or includes either digitalSignature
        /// or nonRepudiation as per RFC 4945, section 5.1.3.2.
        const IKE_COMPLIANT =      0b10000000000;
        /// cert has either CA, AA or OCSP constraint
        const ANY = Self::CA.bits() | Self::AA.bits() | Self::OCSP_SIGNER.bits();
    }
}
