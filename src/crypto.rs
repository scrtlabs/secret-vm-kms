#[cfg(feature = "backtraces")]
use std::backtrace::Backtrace;
use std::fmt::Debug;
use std::result;
use aes_siv::aead::generic_array::GenericArray;
use aes_siv::siv::Aes128Siv;
use log::warn;
use sha2::{Digest, Sha256};
// use x25519_dalek;

#[derive(Debug)]
pub enum CryptoError {
    /// The ECDH process failed.
    DerivingKeyError = 1,
    /// A key was missing.
    MissingKeyError = 2,
    /// The symmetric decryption has failed for some reason.
    DecryptionError = 3,
    /// The ciphertext provided was improper.
    /// e.g. MAC wasn't valid, missing IV etc.
    ImproperEncryption = 4,
    /// The symmetric encryption has failed for some reason.
    EncryptionError = 5,
    /// The signing process has failed for some reason.
    SigningError = 6,
    /// The signature couldn't be parsed correctly.
    ParsingError = 7,
    /// The public key can't be recovered from a message & signature.
    RecoveryError = 8,
    /// A key wasn't valid.
    /// e.g. PrivateKey, PublicKey, SharedSecret.
    KeyError = 9,
    /// The random function had failed generating randomness
    RandomError = 10,
    /// An error related to signature verification
    VerificationError = 11,
    SocketCreationError = 12,
    IPv4LookupError = 13,
    IntelCommunicationError = 14,
    SSSCommunicationError = 15,
    BadResponse = 16,
}
#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Debug)]
pub enum sgx_status_t {
    SGX_SUCCESS                         = 0x0000_0000,

    SGX_ERROR_UNEXPECTED                = 0x0000_0001,      /* Unexpected error */
    SGX_ERROR_INVALID_PARAMETER         = 0x0000_0002,      /* The parameter is incorrect */
    SGX_ERROR_OUT_OF_MEMORY             = 0x0000_0003,      /* Not enough memory is available to complete this operation */
    SGX_ERROR_ENCLAVE_LOST              = 0x0000_0004,      /* Enclave lost after power transition or used in child process created by linux:fork() */
    SGX_ERROR_INVALID_STATE             = 0x0000_0005,      /* SGX API is invoked in incorrect order or state */
    SGX_ERROR_FEATURE_NOT_SUPPORTED     = 0x0000_0008,      /* Feature is not supported on this platform */
    SGX_PTHREAD_EXIT                    = 0x0000_0009,      /* Enclave is exited with pthread_exit() */
    SGX_ERROR_MEMORY_MAP_FAILURE        = 0x0000_000A,      /* Failed to reserve memory for the enclave */

    SGX_ERROR_INVALID_FUNCTION          = 0x0000_1001,      /* The ecall/ocall index is invalid */
    SGX_ERROR_OUT_OF_TCS                = 0x0000_1003,      /* The enclave is out of TCS */
    SGX_ERROR_ENCLAVE_CRASHED           = 0x0000_1006,      /* The enclave is crashed */
    SGX_ERROR_ECALL_NOT_ALLOWED         = 0x0000_1007,      /* The ECALL is not allowed at this time, e.g. ecall is blocked by the dynamic entry table, or nested ecall is not allowed during initialization */
    SGX_ERROR_OCALL_NOT_ALLOWED         = 0x0000_1008,      /* The OCALL is not allowed at this time, e.g. ocall is not allowed during exception handling */
    SGX_ERROR_STACK_OVERRUN             = 0x0000_1009,      /* The enclave is running out of stack */

    SGX_ERROR_UNDEFINED_SYMBOL          = 0x0000_2000,      /* The enclave image has undefined symbol. */
    SGX_ERROR_INVALID_ENCLAVE           = 0x0000_2001,      /* The enclave image is not correct. */
    SGX_ERROR_INVALID_ENCLAVE_ID        = 0x0000_2002,      /* The enclave id is invalid */
    SGX_ERROR_INVALID_SIGNATURE         = 0x0000_2003,      /* The signature is invalid */
    SGX_ERROR_NDEBUG_ENCLAVE            = 0x0000_2004,      /* The enclave is signed as product enclave, and can not be created as debuggable enclave. */
    SGX_ERROR_OUT_OF_EPC                = 0x0000_2005,      /* Not enough EPC is available to load the enclave */
    SGX_ERROR_NO_DEVICE                 = 0x0000_2006,      /* Can't open SGX device */
    SGX_ERROR_MEMORY_MAP_CONFLICT       = 0x0000_2007,      /* Page mapping failed in driver */
    SGX_ERROR_INVALID_METADATA          = 0x0000_2009,      /* The metadata is incorrect. */
    SGX_ERROR_DEVICE_BUSY               = 0x0000_200C,      /* Device is busy, mostly EINIT failed. */
    SGX_ERROR_INVALID_VERSION           = 0x0000_200D,      /* Metadata version is inconsistent between uRTS and sgx_sign or uRTS is incompatible with current platform. */
    SGX_ERROR_MODE_INCOMPATIBLE         = 0x0000_200E,      /* The target enclave 32/64 bit mode or sim/hw mode is incompatible with the mode of current uRTS. */
    SGX_ERROR_ENCLAVE_FILE_ACCESS       = 0x0000_200F,      /* Can't open enclave file. */
    SGX_ERROR_INVALID_MISC              = 0x0000_2010,      /* The MiscSelct/MiscMask settings are not correct.*/
    SGX_ERROR_INVALID_LAUNCH_TOKEN      = 0x0000_2011,      /* The launch token is not correct.*/

    SGX_ERROR_MAC_MISMATCH              = 0x0000_3001,      /* Indicates verification error for reports, sealed datas, etc */
    SGX_ERROR_INVALID_ATTRIBUTE         = 0x0000_3002,      /* The enclave is not authorized, e.g., requesting invalid attribute or launch key access on legacy SGX platform without FLC.  */
    SGX_ERROR_INVALID_CPUSVN            = 0x0000_3003,      /* The cpu svn is beyond platform's cpu svn value */
    SGX_ERROR_INVALID_ISVSVN            = 0x0000_3004,      /* The isv svn is greater than the enclave's isv svn */
    SGX_ERROR_INVALID_KEYNAME           = 0x0000_3005,      /* The key name is an unsupported value */

    SGX_ERROR_SERVICE_UNAVAILABLE       = 0x0000_4001,   /* Indicates aesm didn't respond or the requested service is not supported */
    SGX_ERROR_SERVICE_TIMEOUT           = 0x0000_4002,   /* The request to aesm timed out */
    SGX_ERROR_AE_INVALID_EPIDBLOB       = 0x0000_4003,   /* Indicates epid blob verification error */
    SGX_ERROR_SERVICE_INVALID_PRIVILEGE = 0x0000_4004,   /*  Enclave not authorized to run, .e.g. provisioning enclave hosted in an app without access rights to /dev/sgx_provision */
    SGX_ERROR_EPID_MEMBER_REVOKED       = 0x0000_4005,   /* The EPID group membership is revoked. */
    SGX_ERROR_UPDATE_NEEDED             = 0x0000_4006,   /* SGX needs to be updated */
    SGX_ERROR_NETWORK_FAILURE           = 0x0000_4007,   /* Network connecting or proxy setting issue is encountered */
    SGX_ERROR_AE_SESSION_INVALID        = 0x0000_4008,   /* Session is invalid or ended by server */
    SGX_ERROR_BUSY                      = 0x0000_400A,   /* The requested service is temporarily not availabe */
    SGX_ERROR_MC_NOT_FOUND              = 0x0000_400C,   /* The Monotonic Counter doesn't exist or has been invalided */
    SGX_ERROR_MC_NO_ACCESS_RIGHT        = 0x0000_400D,   /* Caller doesn't have the access right to specified VMC */
    SGX_ERROR_MC_USED_UP                = 0x0000_400E,   /* Monotonic counters are used out */
    SGX_ERROR_MC_OVER_QUOTA             = 0x0000_400F,   /* Monotonic counters exceeds quota limitation */
    SGX_ERROR_KDF_MISMATCH              = 0x0000_4011,   /* Key derivation function doesn't match during key exchange */
    SGX_ERROR_UNRECOGNIZED_PLATFORM     = 0x0000_4012,   /* EPID Provisioning failed due to platform not recognized by backend server*/
    SGX_ERROR_UNSUPPORTED_CONFIG        = 0x0000_4013,   /* The config for trigging EPID Provisiong or PSE Provisiong&LTP is invalid*/

    SGX_ERROR_NO_PRIVILEGE              = 0x0000_5002,   /* Not enough privilege to perform the operation */

    /* SGX Protected Code Loader Error codes*/
    SGX_ERROR_PCL_ENCRYPTED             = 0x0000_6001,   /* trying to encrypt an already encrypted enclave */
    SGX_ERROR_PCL_NOT_ENCRYPTED         = 0x0000_6002,   /* trying to load a plain enclave using sgx_create_encrypted_enclave */
    SGX_ERROR_PCL_MAC_MISMATCH          = 0x0000_6003,   /* section mac result does not match build time mac */
    SGX_ERROR_PCL_SHA_MISMATCH          = 0x0000_6004,   /* Unsealed key MAC does not match MAC of key hardcoded in enclave binary */
    SGX_ERROR_PCL_GUID_MISMATCH         = 0x0000_6005,   /* GUID in sealed blob does not match GUID hardcoded in enclave binary */

    /* SGX errors are only used in the file API when there is no appropriate EXXX (EINVAL, EIO etc.) error code */
    SGX_ERROR_FILE_BAD_STATUS               = 0x0000_7001,	/* The file is in bad status, run sgx_clearerr to try and fix it */
    SGX_ERROR_FILE_NO_KEY_ID                = 0x0000_7002,	/* The Key ID field is all zeros, can't re-generate the encryption key */
    SGX_ERROR_FILE_NAME_MISMATCH            = 0x0000_7003,	/* The current file name is different then the original file name (not allowed, substitution attack) */
    SGX_ERROR_FILE_NOT_SGX_FILE             = 0x0000_7004,  /* The file is not an SGX file */
    SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE  = 0x0000_7005,	/* A recovery file can't be opened, so flush operation can't continue (only used when no EXXX is returned)  */
    SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE = 0x0000_7006,  /* A recovery file can't be written, so flush operation can't continue (only used when no EXXX is returned)  */
    SGX_ERROR_FILE_RECOVERY_NEEDED          = 0x0000_7007,	/* When openeing the file, recovery is needed, but the recovery process failed */
    SGX_ERROR_FILE_FLUSH_FAILED             = 0x0000_7008,	/* fflush operation (to disk) failed (only used when no EXXX is returned) */
    SGX_ERROR_FILE_CLOSE_FAILED             = 0x0000_7009,	/* fclose operation (to disk) failed (only used when no EXXX is returned) */

    SGX_ERROR_UNSUPPORTED_ATT_KEY_ID        = 0x0000_8001,    /* platform quoting infrastructure does not support the key.*/
    SGX_ERROR_ATT_KEY_CERTIFICATION_FAILURE = 0x0000_8002,    /* Failed to generate and certify the attestation key.*/
    SGX_ERROR_ATT_KEY_UNINITIALIZED         = 0x0000_8003,    /* The platform quoting infrastructure does not have the attestation key available to generate quote.*/
    SGX_ERROR_INVALID_ATT_KEY_CERT_DATA     = 0x0000_8004,    /* TThe data returned by the platform library's sgx_get_quote_config() is invalid.*/
    SGX_ERROR_PLATFORM_CERT_UNAVAILABLE     = 0x0000_8005,    /* The PCK Cert for the platform is not available.*/

    SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED = 0x0000_F001, /* The ioctl for enclave_create unexpectedly failed with EINTR. */

    SGX_ERROR_WASM_BUFFER_TOO_SHORT         = 0x0F00_F001,   /* sgxwasm output buffer not long enough */
    SGX_ERROR_WASM_INTERPRETER_ERROR        = 0x0F00_F002,   /* sgxwasm interpreter error */
    SGX_ERROR_WASM_LOAD_MODULE_ERROR        = 0x0F00_F003,   /* sgxwasm loadmodule error */
    SGX_ERROR_WASM_TRY_LOAD_ERROR           = 0x0F00_F004,   /* sgxwasm tryload error */
    SGX_ERROR_WASM_REGISTER_ERROR           = 0x0F00_F005,   /* sgxwasm register error */
    SGX_ERROR_FAAS_BUFFER_TOO_SHORT         = 0x0F00_E001,   /* faas output buffer not long enough */
    SGX_ERROR_FAAS_INTERNAL_ERROR           = 0x0F00_E002,   /* faas exec internal error */
}

extern "C" {
     pub fn sgx_read_rand(rand: *mut u8, length_in_bytes: usize) -> sgx_status_t;
}

pub type SgxError = result::Result<(), sgx_status_t>;

pub fn rsgx_read_rand(rand: &mut [u8]) -> SgxError {
    // let ret = unsafe { sgx_read_rand(rand.as_mut_ptr(), rand.len()) }
    let ret = sgx_status_t::SGX_SUCCESS ;
    match ret {
        sgx_status_t::SGX_SUCCESS => Ok(()),
        _ => Err(ret),
    }
}
pub fn rand_slice(rand: &mut [u8]) -> Result<(), CryptoError> {
    rsgx_read_rand(rand).map_err(|_e| CryptoError::RandomError {})
}

/// New helper: a deterministic rand_slice which fills `rand` using a given seed.
/// It repeatedly hashes the current value to generate enough pseudorandom bytes.
pub fn rand_slice_with_seed(rand: &mut [u8], seed: &[u8]) -> Result<(), CryptoError> {
    let mut current = seed.to_vec();
    let mut offset = 0;
    while offset < rand.len() {
        let hash = Sha256::digest(&current);
        let bytes_to_copy = std::cmp::min(rand.len() - offset, hash.len());
        rand[offset..offset + bytes_to_copy].copy_from_slice(&hash[..bytes_to_copy]);
        offset += bytes_to_copy;
        current = hash.to_vec();
    }
    Ok(())
}

pub const SECRET_KEY_SIZE: usize = 32;
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const SGX_ECP256_KEY_SIZE: usize = 32;

#[derive(Copy, Clone, Default)]
pub struct sgx_ec256_private_t {
    pub r: [u8; SGX_ECP256_KEY_SIZE],
}
pub type SymmetricKey = [u8; SYMMETRIC_KEY_SIZE];
pub type DhKey = SymmetricKey;
#[repr(C, align(64))]
#[derive(Copy, Clone, Default)]
pub struct sgx_align_ec256_private_t {
    _pad: [u8; 8],
    pub key: sgx_ec256_private_t,
}
type AlignedEc256PrivateKey = sgx_align_ec256_private_t;
pub type Ed25519PublicKey = [u8; 32];
#[repr(C, align(64))]
#[derive(Clone, Copy, Default)]
pub struct Ed25519PrivateKey {
    pub key: AlignedEc256PrivateKey,
}

impl Ed25519PrivateKey {
    pub fn to_owned(self) -> AlignedEc256PrivateKey {
        self.key
    }

    pub fn get_mut(&mut self) -> &mut [u8; SECRET_KEY_SIZE] {
        &mut self.key.key.r as &mut [u8; SECRET_KEY_SIZE]
    }
}

pub const EC_256_PRIVATE_KEY_SIZE: usize = 32;

pub trait ExportECKey {
    fn key_ref(&self) -> &[u8; EC_256_PRIVATE_KEY_SIZE];
}

impl ExportECKey for Ed25519PrivateKey {
    fn key_ref(&self) -> &[u8; EC_256_PRIVATE_KEY_SIZE] {
        &self.key.key.r as &[u8; EC_256_PRIVATE_KEY_SIZE]
    }
}

#[derive(Clone, Copy, Default)]
pub struct KeyPair {
    secret_key: Ed25519PrivateKey,
    public_key: Ed25519PublicKey,
}

impl KeyPair {
    pub fn new() -> Result<Self, CryptoError> {
        let mut secret_key = Ed25519PrivateKey::default();
        rand_slice(secret_key.get_mut())?;

        let sk = x25519_dalek::StaticSecret::from(secret_key.to_owned().key.r as [u8; 32]);
        let pk = x25519_dalek::PublicKey::from(&sk);

        Ok(Self {
            secret_key,
            public_key: *pk.as_bytes(),
        })
    }
    /// Create a new key pair using the provided seed.
    /// The seed is used to fill the secret key deterministically.
    pub fn new_with_seed(seed: [u8; SECRET_KEY_SIZE]) -> Result<Self, CryptoError> {
        let mut secret_key = Ed25519PrivateKey::default();
        // Instead of using SGX randomness, fill secret_key using the given seed.
        rand_slice_with_seed(secret_key.get_mut(), &seed)?;
        let sk = x25519_dalek::StaticSecret::from(*secret_key.get_mut());
        let pk = x25519_dalek::PublicKey::from(&sk);
        Ok(Self {
            secret_key,
            public_key: *pk.as_bytes(),
        })
    }

    pub fn diffie_hellman(&self, your_public: &[u8; SECRET_KEY_SIZE]) -> DhKey {
        let my_secret =
            x25519_dalek::StaticSecret::from(self.secret_key.to_owned().key.r as [u8; 32]);
        let pk = x25519_dalek::PublicKey::from(*your_public);
        let ss = my_secret.diffie_hellman(&pk);

        *ss.as_bytes()
    }
    pub fn get_privkey(&self) -> &[u8; SECRET_KEY_SIZE] {
        self.secret_key.key_ref()
    }

    // This will return the raw 64 bytes public key.
    pub fn get_pubkey(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.public_key
    }
}

pub const SYMMETRIC_KEY_SIZE: usize = 256 / 8;
type AlignedKey = sgx_align_ec256_private_t;

#[repr(C, align(64))]
#[derive(Clone, Copy, Default)]
pub struct AESKey {
    pub key: AlignedKey,
}

impl AESKey {
    #[allow(dead_code)]
    fn key_len() -> usize {
        SYMMETRIC_KEY_SIZE
    }

    pub fn get(&self) -> &[u8; SYMMETRIC_KEY_SIZE] {
        &self.key.key.r as &[u8; SYMMETRIC_KEY_SIZE]
    }

    pub fn new_from_slice(privkey: &[u8; SYMMETRIC_KEY_SIZE]) -> Self {
        let mut key = AESKey::default();

        key.as_mut().copy_from_slice(privkey);

        key
    }
}

impl AsMut<[u8; SYMMETRIC_KEY_SIZE]> for AESKey {
    fn as_mut(&mut self) -> &mut [u8; SYMMETRIC_KEY_SIZE] {
        &mut self.key.key.r as &mut [u8; SYMMETRIC_KEY_SIZE]
    }
}

pub trait SIVEncryptable {
    fn encrypt_siv(&self, plaintext: &[u8], ad: Option<&[&[u8]]>) -> Result<Vec<u8>, CryptoError>;
    fn decrypt_siv(&self, plaintext: &[u8], ad: Option<&[&[u8]]>) -> Result<Vec<u8>, CryptoError>;
}

impl SIVEncryptable for AESKey {
    fn encrypt_siv(&self, plaintext: &[u8], ad: Option<&[&[u8]]>) -> Result<Vec<u8>, CryptoError> {
        aes_siv_encrypt(plaintext, ad, self.get())
    }

    fn decrypt_siv(&self, plaintext: &[u8], ad: Option<&[&[u8]]>) -> Result<Vec<u8>, CryptoError> {
        aes_siv_decrypt(plaintext, ad, self.get())
    }
}

fn aes_siv_encrypt(
    plaintext: &[u8],
    ad: Option<&[&[u8]]>,
    key: &SymmetricKey,
) -> Result<Vec<u8>, CryptoError> {
    let ad = ad.unwrap_or(&[&[]]);

    let mut cipher = Aes128Siv::new(GenericArray::clone_from_slice(key));
    cipher.encrypt(ad, plaintext).map_err(|e| {
        warn!("aes_siv_encrypt error: {:?}", e);
        CryptoError::EncryptionError
    })
}

fn aes_siv_decrypt(
    ciphertext: &[u8],
    ad: Option<&[&[u8]]>,
    key: &SymmetricKey,
) -> Result<Vec<u8>, CryptoError> {
    let ad = ad.unwrap_or(&[&[]]);

    let mut cipher = Aes128Siv::new(GenericArray::clone_from_slice(key));
    cipher.decrypt(ad, ciphertext).map_err(|e| {
        warn!("aes_siv_decrypt error: {:?}", e);
        CryptoError::DecryptionError
    })
}