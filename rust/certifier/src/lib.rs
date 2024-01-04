use std::str::FromStr;
use chrono::{
    Utc,
    Duration,
    DateTime,
    Datelike,
};
use der::{
    Decode,
    Encode,
    asn1::GeneralizedTime,
};
use loga::{
    ea,
    ResultContext,
};
use rand::RngCore;
use sec1::EcParameters;
use serde::{
    Serialize,
    Deserialize,
};
use sha2::{
    Digest,
    Sha256,
    Sha512,
    Sha384,
};
use signature::Keypair;
use x509_cert::{
    spki::{
        SubjectPublicKeyInfoOwned,
        EncodePublicKey,
        DynSignatureAlgorithmIdentifier,
    },
    name::RdnSequence,
    serial_number::SerialNumber,
};

pub const ENV_ROTATE_CONFIG: &'static str = "CERTIPASTA_ROTATE_CONFIG";
pub const ENV_SERVER_CONFIG: &'static str = "CERTIPASTA_CONFIG";

#[derive(Serialize, Deserialize)]
pub struct RotateConfig {
    pub bucket: String,
    pub key_gcpid: String,
}

#[derive(Serialize, Deserialize)]
pub struct ServerConfig {
    pub key_gcpid: String,
}

pub fn sign_duration() -> Duration {
    return Duration::days(90);
}

pub fn rotation_period() -> Duration {
    return Duration::days(365);
}

pub fn rotation_buffer() -> Duration {
    return Duration::days(7);
}

pub fn ca_rdn() -> RdnSequence {
    return RdnSequence::from_str("CN=certifiedpasta,O=andrewbaxter").unwrap();
}

pub fn rand_serial() -> SerialNumber {
    let mut data = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut data);

    // Big-endian positive, for whatever meaning the spec has remaining
    data[0] &= 0x7F;
    return SerialNumber::new(&data).unwrap();
}

#[macro_export]
macro_rules! enum_unwrap{
    ($i: expr, $p: pat => $o: expr) => {
        match $i {
            $p => $o,
            _ => panic !(""),
        }
    };
}

pub fn to_x509_time(t: DateTime<Utc>) -> x509_cert::time::Time {
    return x509_cert::time::Time::GeneralTime(
        GeneralizedTime::from_date_time(
            der::DateTime::new(t.year() as u16, t.month() as u8, t.day() as u8, 0, 0, 0).unwrap(),
        ),
    );
}

#[derive(Clone)]
pub struct BuilderPubKey(pub SubjectPublicKeyInfoOwned);

impl EncodePublicKey for BuilderPubKey {
    fn to_public_key_der(&self) -> x509_cert::spki::Result<x509_cert::spki::Document> {
        return Ok(der::Document::from_der(&self.0.to_der().unwrap()).unwrap());
    }
}

pub struct BuilderSigner(pub BuilderPubKey);

impl Keypair for BuilderSigner {
    type VerifyingKey = BuilderPubKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        return self.0.clone();
    }
}

impl DynSignatureAlgorithmIdentifier for BuilderSigner {
    fn signature_algorithm_identifier(&self) -> x509_cert::spki::Result<x509_cert::spki::AlgorithmIdentifierOwned> {
        return Ok(self.0.0.algorithm.clone());
    }
}

pub fn spki_compute_digest(
    spki: &SubjectPublicKeyInfoOwned,
    der: &[u8],
) -> Result<google_cloudkms1::api::Digest, loga::Error> {
    let oid = spki.algorithm.oid.to_string();
    match oid.as_str() {
        // ecPublicKey
        "1.2.840.10045.2.1" => {
            let curve =
                EcParameters::from_der(
                    &spki.algorithm.parameters.as_ref().context("Missing ecPublicKey parameters")?.to_der().unwrap(),
                )
                    .context("Error parsing ecPublicKey params")?
                    .named_curve()
                    .context("ecPublicKey params missing curve name")?
                    .to_string();
            match curve.as_str() {
                // ECDSA_P256
                "1.2.840.10045.3.1.7" => {
                    return Ok(google_cloudkms1::api::Digest {
                        sha256: Some(<Sha256 as Digest>::digest(der).to_vec()),
                        ..Default::default()
                    });
                },
                // ECDSA_P384
                "1.3.132.0.34" => {
                    return Ok(google_cloudkms1::api::Digest {
                        sha384: Some(<Sha384 as Digest>::digest(der).to_vec()),
                        ..Default::default()
                    });
                },
                // ECDSA_P521
                "1.3.132.0.35" => {
                    return Ok(google_cloudkms1::api::Digest {
                        sha512: Some(<Sha512 as Digest>::digest(der).to_vec()),
                        ..Default::default()
                    });
                },
                _ => {
                    return Err(loga::err_with("ecPublicKey has unsupported curve", ea!(curve = curve)));
                },
            }
        },
        _ => {
            return Err(loga::err_with("Configured key has unsupported algorithm", ea!(oid = oid)));
        },
    }
}
