use std::{
    io::{
        Cursor,
    },
    str::FromStr,
    path::PathBuf,
};
use aargvark::{
    Aargvark,
    AargvarkJson,
};
use certifier::{
    sign_duration,
    rotation_period,
    rotation_buffer,
    spki_compute_digest,
    to_x509_time,
    ca_rdn,
    rand_serial,
    BuilderSigner,
    BuilderPubKey,
    RotateConfig,
    ENV_ROTATE_CONFIG,
};
use chrono::{
    DateTime,
    Utc,
    Duration,
};
use der::{
    DecodePem,
    EncodePem,
};
use google_cloudkms1::{
    CloudKMS,
    api::{
        CryptoKeyVersion,
        UpdateCryptoKeyPrimaryVersionRequest,
        DestroyCryptoKeyVersionRequest,
        AsymmetricSignRequest,
    },
};
use google_storage1::{
    Storage,
    api::Object,
};
use loga::{
    ResultContext,
    ea,
};
use mime::Mime;
use spaghettinuum::bb;
use tokio::fs::{
    create_dir_all,
    write,
};
use x509_cert::{
    ext::pkix::{
        name::GeneralName,
        NameConstraints,
        constraints::name::GeneralSubtree,
    },
    der::asn1::{
        Ia5String,
        BitString,
    },
    builder::{
        Builder,
        CertificateBuilder,
        Profile,
    },
    spki::SubjectPublicKeyInfoOwned,
};
use yup_oauth2::{
    ApplicationDefaultCredentialsAuthenticator,
    ApplicationDefaultCredentialsFlowOpts,
    authenticator::ApplicationDefaultCredentialsTypes,
};

#[derive(Aargvark)]
struct Args {
    pub config: Option<AargvarkJson<RotateConfig>>,
}

#[tokio::main]
async fn main() {
    async fn inner() -> Result<(), loga::Error> {
        let args = aargvark::vark::<Args>();
        let log = &loga::new(loga::Level::Info);
        let config = if let Some(p) = args.config {
            p.value
        } else if let Some(c) = match std::env::var(ENV_ROTATE_CONFIG) {
            Ok(c) => Some(c),
            Err(e) => match e {
                std::env::VarError::NotPresent => None,
                std::env::VarError::NotUnicode(_) => {
                    return Err(loga::err_with("Error parsing env var as unicode", ea!(env = ENV_ROTATE_CONFIG)))
                },
            },
        } {
            let log = log.fork(ea!(source = "env"));
            serde_json::from_str::<RotateConfig>(&c).log_context(&log, "Parsing config")?
        } else {
            return Err(
                log.new_err_with(
                    "No config passed on command line, and no config set in env var",
                    ea!(env = ENV_ROTATE_CONFIG),
                ),
            );
        };
        let hc =
            hyper
            ::Client
            ::builder().build(
                hyper_rustls::HttpsConnectorBuilder::new().with_webpki_roots().https_or_http().enable_http1().build(),
            );
        let auth =
            match ApplicationDefaultCredentialsAuthenticator::with_client(
                ApplicationDefaultCredentialsFlowOpts::default(),
                hc.clone(),
            ).await {
                ApplicationDefaultCredentialsTypes::InstanceMetadata(auth) => auth
                    .build()
                    .await
                    .expect("Unable to create instance metadata authenticator"),
                ApplicationDefaultCredentialsTypes::ServiceAccount(auth) => auth
                    .build()
                    .await
                    .expect("Unable to create service account authenticator"),
            };
        let kms_client = CloudKMS::new(hc.clone(), auth.clone());
        let storage_client = Storage::new(hc, auth);

        // # Generate a new CA cert version, add to bucket
        {
            // Generate new keypair version + get public key
            let (_, version) =
                kms_client
                    .projects()
                    .locations_key_rings_crypto_keys_crypto_key_versions_create(
                        CryptoKeyVersion::default(),
                        &config.key_gcpid,
                    )
                    .doit()
                    .await
                    .log_context(log, "Error rotating key")?;
            let version_created =
                version.create_time.log_context(log, "Google failed to return new key version create time")?;
            let version_name = version.name.unwrap();
            let (_, pubkey) =
                kms_client
                    .projects()
                    .locations_key_rings_crypto_keys_crypto_key_versions_get_public_key(&version_name)
                    .doit()
                    .await
                    .log_context(log, "Failed to get new public key")?;

            // Build CA cert
            let signer_spki = SubjectPublicKeyInfoOwned::from_pem(&pubkey.pem.unwrap()).unwrap();
            let builder_signer = BuilderSigner(BuilderPubKey(signer_spki.clone()));
            let mut ca_builder = CertificateBuilder::new(
                Profile::Root,
                // Timestamp, 1h granularity (don't publish two issued within an hour/don't issue
                // two within an hour)
                rand_serial(),
                x509_cert::time::Validity {
                    not_before: to_x509_time(version_created - Duration::hours(24)),
                    not_after: to_x509_time(
                        version_created + rotation_period() * 2 + rotation_buffer() + sign_duration(),
                    ),
                },
                ca_rdn(),
                signer_spki.clone(),
                &builder_signer,
            ).unwrap();
            ca_builder.add_extension(&NameConstraints {
                permitted_subtrees: Some(vec![GeneralSubtree {
                    base: GeneralName::DnsName(Ia5String::new(".s").unwrap()),
                    minimum: 0,
                    maximum: None,
                }]),
                excluded_subtrees: None,
            }).unwrap();
            let ca_csr_der = ca_builder.finalize().unwrap();
            let signature =
                kms_client
                    .projects()
                    .locations_key_rings_crypto_keys_crypto_key_versions_asymmetric_sign(AsymmetricSignRequest {
                        digest: Some(
                            spki_compute_digest(
                                &signer_spki,
                                &ca_csr_der,
                            ).log_context(log, "Error generating digest to sign CSR")?,
                        ),
                        ..Default::default()
                    }, &version_name)
                    .doit()
                    .await
                    .log_context(log, "Error signing new CA cert CSR")?
                    .1
                    .signature
                    .log_context(log, "Signing request response missing signature data")?;
            let ca_pem =
                ca_builder
                    .assemble(
                        BitString::from_bytes(&signature).log_context(log, "Error building signature bitstring")?,
                    )
                    .log_context(log, "Error assembling cert")?
                    .to_pem(der::pem::LineEnding::LF)
                    .log_context(log, "Error building PEM for cert")?;

            // Log and store
            println!("{}", ca_pem);
            storage_client
                .objects()
                .insert(Object {
                    name: Some(version_created.to_rfc3339()),
                    ..Default::default()
                }, &config.bucket)
                .upload_resumable(Cursor::new(ca_pem.as_bytes()), Mime::from_str("application/x-pem-file").unwrap())
                .await
                .log_context(log, "Error uploading new cert")?;
        }

        // # Manage existing key versions
        struct LocalVersion {
            id: String,
            create_time: DateTime<Utc>,
        }

        let mut versions = vec![];
        {
            let mut after = <Option<String>>::None;
            loop {
                let mut req =
                    kms_client
                        .projects()
                        .locations_key_rings_crypto_keys_crypto_key_versions_list(&config.key_gcpid);
                if let Some(after) = after {
                    req = req.page_token(&after);
                }
                let (_, page) =
                    req.doit().await.log_context(log, "Failed to retrieve key versions to update to semi-latest")?;
                let Some(new_versions) = page.crypto_key_versions else {
                    break;
                };
                for v in new_versions {
                    let Some(id) = v.name else {
                        eprintln!("Received version missing name/id! Skipping...");
                        continue;
                    };
                    let Some(create_time) = v.create_time else {
                        eprintln!("Received version missing create time! Skipping...");
                        continue;
                    };
                    versions.push(LocalVersion {
                        id: id,
                        create_time: create_time,
                    });
                }
                after = page.next_page_token.map(|x| x.to_string());
                if after.is_none() {
                    break;
                }
            }
        }

        bb!{
            versions.sort_by_cached_key(|e| e.create_time);
            let mut iter = versions.into_iter().rev();
            {
                // Skip final, nothing to do there
                let Some(_) = iter.next() else {
                    break;
                };
            }
            {
                // Make semifinal primary
                let Some(semifinal_v) = iter.next() else {
                    break;
                };
                kms_client
                    .projects()
                    .locations_key_rings_crypto_keys_update_primary_version(
                        UpdateCryptoKeyPrimaryVersionRequest { crypto_key_version_id: Some(semifinal_v.id.clone()) },
                        &config.key_gcpid,
                    )
                    .doit()
                    .await
                    .log_context_with(
                        log,
                        "Failed to set semifinal key version as primary",
                        ea!(id = semifinal_v.id),
                    )?;
            }

            // Delete older certs
            for v in iter {
                kms_client
                    .projects()
                    .locations_key_rings_crypto_keys_crypto_key_versions_destroy(
                        DestroyCryptoKeyVersionRequest::default(),
                        &v.id,
                    )
                    .doit()
                    .await
                    .log_context_with(log, "Failed to destroy older key", ea!(id = v.id))?;
            }
            break;
        };

        // # Manage bucket versions and get all the active certs
        struct LocalObject {
            id: String,
            create_time: DateTime<Utc>,
        }

        let mut objects = vec![];
        {
            let mut after = <Option<String>>::None;
            loop {
                let mut req = storage_client.objects().list(&config.bucket);
                if let Some(after) = after {
                    req = req.page_token(&after);
                }
                let (_, page) = req.doit().await.log_context(log, "Failed to retrieve cert bucket page")?;
                let Some(new_objects) = page.items else {
                    break;
                };
                for v in new_objects {
                    let Some(id) = v.name else {
                        eprintln!("Received obj missing name/id! Skipping...");
                        continue;
                    };
                    let create_time =
                        DateTime::parse_from_rfc3339(
                            &id,
                        ).log_context(log, "Error parsing object key as expected RFC3339 creation timestamp")?;
                    objects.push(LocalObject {
                        id: id,
                        create_time: create_time.into(),
                    });
                }
                after = page.next_page_token.map(|x| x.to_string());
                if after.is_none() {
                    break;
                }
            }
        }
        objects.sort_by_cached_key(|e| e.create_time);

        // Epoch is the oldest time a customer cert signed with a CA cert could exist.  CA
        // certs start being used 1 rotation period in, and can sign certs for 1 rotation,
        // plus the duration of a cert signed at the very end of that life.
        let artifacts_root = PathBuf::from("artifacts");
        create_dir_all(&artifacts_root).await.log_context(log, "Error creating artifacts dir")?;
        let epoch = Utc::now() - (sign_duration() + rotation_period() * 2);
        for o in objects.into_iter().rev() {
            let log = &log.fork(ea!(task = "manage_certs", id = o.id));
            if o.create_time < epoch {
                log.info("Deleting no longer in-use cert", ea!(created = o.create_time, epoch = epoch));
                storage_client
                    .objects()
                    .delete(&config.bucket, &o.id)
                    .doit()
                    .await
                    .log_context(log, "Error deleting inactive cert")?;
            } else {
                let resp =
                    storage_client
                        .objects()
                        .get(&config.bucket, &o.id)
                        .param("alt", "media")
                        .doit()
                        .await
                        .log_context(log, "Error requesting cert from bucket")?
                        .0;
                if !resp.status().is_success() {
                    return Err(log.new_err("Received error response to request for cert"))
                }
                let body =
                    hyper::body::to_bytes(resp.into_body()).await.log_context(log, "Error downloading cert body")?;
                write(artifacts_root.join(format!("spaghettinuum_s_{}.pem", o.create_time)), body)
                    .await
                    .log_context(log, "Error writing active cert PEM")?;
            }
        }
        return Ok(());
    }

    match inner().await {
        Ok(_) => { },
        Err(e) => {
            loga::fatal(e);
        },
    }
}
