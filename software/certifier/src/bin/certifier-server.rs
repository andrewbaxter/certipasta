use std::{
    net::{
        SocketAddr,
        SocketAddrV4,
        Ipv4Addr,
        IpAddr,
    },
    sync::{
        Arc,
    },
    str::FromStr,
    num::NonZeroU32,
};
use aargvark::{
    Aargvark,
    AargvarkJson,
};
use certifier::{
    sign_duration,
    to_x509_time,
    ca_rdn,
    rand_serial,
    BuilderSigner,
    BuilderPubKey,
    enum_unwrap,
    ENV_SERVER_CONFIG,
    ServerConfig,
    VERSION_STATE_ENABLED,
    decide_sig,
    WARN,
    INFO,
};
use chrono::{
    Utc,
    Duration,
    DateTime,
};
use der::{
    asn1::BitString,
    EncodePem,
    DecodePem,
    Decode,
};
use google_cloudkms1::{
    CloudKMS,
    api::AsymmetricSignRequest,
};
use governor::{
    RateLimiter,
    Quota,
};
use hyper::{
    client::HttpConnector,
    StatusCode,
};
use hyper_rustls::HttpsConnector;
use loga::{
    ea,
    ResultContext,
};
use poem::{
    listener::TcpListener,
    Server,
    Route,
    post,
    Response,
    web::{
        Data,
        RemoteAddr,
    },
    EndpointExt,
    middleware::AddData,
    handler,
    IntoResponse,
    Addr,
};
use rand::RngCore;
use spaghettinuum::interface::{
    identity::Identity,
    certify_protocol::{
        latest::CertResponse,
        CertRequest,
    },
};
use x509_cert::{
    builder::{
        CertificateBuilder,
        Profile,
        Builder,
    },
    name::RdnSequence,
    spki::SubjectPublicKeyInfoOwned,
};
use yup_oauth2::{
    ApplicationDefaultCredentialsAuthenticator,
    ApplicationDefaultCredentialsFlowOpts,
    authenticator::ApplicationDefaultCredentialsTypes,
};

async fn generate_cert(
    now: DateTime<Utc>,
    identity: &Identity,
    spki_der: &[u8],
    kms_key_gcpid: &str,
    kms_client: &CloudKMS<HttpsConnector<HttpConnector>>,
) -> Result<CertResponse, loga::Error> {
    let log = &loga::StandardLog::new().with_flags(WARN | INFO).fork(ea!(id = identity.to_string()));
    let requester_keyinfo =
        SubjectPublicKeyInfoOwned::from_der(spki_der).stack_context(log, "Unable to parse SPKI DER")?;
    let (_, ca_keylist) =
        kms_client
            .projects()
            .locations_key_rings_crypto_keys_crypto_key_versions_list(kms_key_gcpid)
            .filter(&format!("state={}", VERSION_STATE_ENABLED))
            .page_size(2)
            .doit()
            .await
            .stack_context(log, "Failed to get keys info")?;
    let mut ca_keylist =
        ca_keylist
            .crypto_key_versions
            .stack_context(log, "Missing items in crypto key version list response")?
            .into_iter()
            .filter_map(|k| match (k.create_time, k.name) {
                (Some(t), Some(n)) => Some((t, n)),
                _ => None,
            })
            .collect::<Vec<_>>();
    ca_keylist.sort_by_cached_key(|k| k.0);
    let ca_current_privkey_full_id =
        ca_keylist
            .pop()
            .stack_context(
                log,
                "No primary key set in keys, can't sign (keys missing critical fields in response may have been filtered)",
            )?
            .1;
    let (_, ca_pubkey) =
        kms_client
            .projects()
            .locations_key_rings_crypto_keys_crypto_key_versions_get_public_key(&ca_current_privkey_full_id)
            .doit()
            .await
            .stack_context(log, "Failed to get public key")?;
    let ca_keyinfo = SubjectPublicKeyInfoOwned::from_pem(&ca_pubkey.pem.unwrap()).unwrap();
    let (sig_digest_fn, sig_algorithm) = decide_sig(&ca_keyinfo)?;
    let ca_signer = BuilderSigner {
        key: BuilderPubKey(ca_keyinfo.clone()),
        alg: sig_algorithm,
    };
    let mut cert_builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: ca_rdn(),
            enable_key_agreement: true,
            enable_key_encipherment: true,
        },
        // Timestamp, 1h granularity (don't publish two issued within an hour/don't issue
        // two within an hour)
        rand_serial(),
        x509_cert::time::Validity {
            not_before: to_x509_time(now),
            not_after: to_x509_time(now + sign_duration()),
        },
        RdnSequence::from_str(&format!("CN={}.s", identity.to_string())).unwrap(),
        requester_keyinfo,
        &ca_signer,
    ).unwrap();
    let csr_der = cert_builder.finalize().unwrap();
    let signature =
        kms_client
            .projects()
            .locations_key_rings_crypto_keys_crypto_key_versions_asymmetric_sign(AsymmetricSignRequest {
                digest: Some(sig_digest_fn(&csr_der)),
                ..Default::default()
            }, &ca_current_privkey_full_id)
            .doit()
            .await
            .stack_context(log, "Error signing new CA cert CSR")?
            .1
            .signature
            .stack_context(log, "Signing request response missing signature data")?;
    let pem =
        cert_builder
            .assemble(BitString::from_bytes(&signature).stack_context(log, "Error building signature bitstring")?)
            .stack_context(log, "Error assembling cert")?
            .to_pem(der::pem::LineEnding::LF)
            .stack_context(log, "Error building PEM for cert")?;
    return Ok(CertResponse { pub_pem: pem });
}

#[derive(Aargvark)]
struct Args {
    pub config: Option<AargvarkJson<ServerConfig>>,
}

#[tokio::main]
async fn main() {
    async fn inner() -> Result<(), loga::Error> {
        let args = aargvark::vark::<Args>();
        let log = &loga::StandardLog::new().with_flags(WARN | INFO);
        let config = if let Some(p) = args.config {
            p.value
        } else if let Some(c) = match std::env::var(ENV_SERVER_CONFIG) {
            Ok(c) => Some(c),
            Err(e) => match e {
                std::env::VarError::NotPresent => None,
                std::env::VarError::NotUnicode(_) => {
                    return Err(loga::err_with("Error parsing env var as unicode", ea!(env = ENV_SERVER_CONFIG)))
                },
            },
        } {
            let log = log.fork(ea!(source = "env"));
            serde_json::from_str::<ServerConfig>(&c).stack_context(&log, "Parsing config")?
        } else {
            return Err(
                log.err_with(
                    "No config passed on command line, and no config set in env var",
                    ea!(env = ENV_SERVER_CONFIG),
                ),
            );
        };
        let tm = taskmanager::TaskManager::new();
        let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 80));
        tm.critical_task({
            let log = log.fork(ea!(subsys = "http", addr = bind_addr));
            let tm1 = tm.clone();
            {
                let mut x = [0u8; 1];
                rand::thread_rng().fill_bytes(&mut x);
            }
            let hyper_client =
                hyper
                ::Client
                ::builder().build(
                    hyper_rustls::HttpsConnectorBuilder::new()
                        .with_webpki_roots()
                        .https_or_http()
                        .enable_http1()
                        .build(),
                );
            let kms_client =
                CloudKMS::new(
                    hyper_client.clone(),
                    match ApplicationDefaultCredentialsAuthenticator::with_client(
                        ApplicationDefaultCredentialsFlowOpts::default(),
                        hyper_client,
                    ).await {
                        ApplicationDefaultCredentialsTypes::InstanceMetadata(auth) => auth
                            .build()
                            .await
                            .expect("Unable to create instance metadata authenticator"),
                        ApplicationDefaultCredentialsTypes::ServiceAccount(auth) => auth
                            .build()
                            .await
                            .expect("Unable to create service account authenticator"),
                    },
                );

            struct State_ {
                log: loga::StandardLog,
                kms_key_gcpid: String,
                kms_client: CloudKMS<HttpsConnector<HttpConnector>>,
                ip_limit: RateLimiter<
                    IpAddr,
                    governor::state::keyed::DefaultKeyedStateStore<IpAddr>,
                    governor::clock::DefaultClock,
                >,
                ident_limit: RateLimiter<
                    Identity,
                    governor::state::keyed::DefaultKeyedStateStore<Identity>,
                    governor::clock::DefaultClock,
                >,
            }

            #[derive(Clone)]
            struct State(Arc<State_>);

            async move {
                match tm1.if_alive(Server::new(TcpListener::bind(&bind_addr)).run(Route::new().at("/", post({
                    #[handler]
                    async fn ep(Data(state): Data<&State>, remote: &RemoteAddr, body: Vec<u8>) -> Response {
                        let body = match serde_json::from_slice::<CertRequest>(&body) {
                            Ok(b) => b,
                            Err(_) => {
                                return StatusCode::BAD_REQUEST.into_response();
                            },
                        };
                        let state = state.clone().0;
                        if state
                            .ip_limit
                            .check_key(&enum_unwrap!(&remote.0, Addr:: SocketAddr(x) => x.ip()))
                            .is_err() {
                            return StatusCode::TOO_MANY_REQUESTS.into_response();
                        }
                        let inner = async {
                            let now = Utc::now();
                            match body {
                                CertRequest::V1(req) => {
                                    let Ok(req_params) = req.params.verify(&req.identity) else {
                                        return Ok(StatusCode::BAD_REQUEST.into_response()) as
                                            Result<_, loga::Error>;
                                    };
                                    if now.signed_duration_since(req_params.stamp) > Duration::seconds(60) {
                                        return Ok(StatusCode::BAD_REQUEST.into_response());
                                    }
                                    if state.ident_limit.check_key(&req.identity).is_err() {
                                        return Ok(StatusCode::TOO_MANY_REQUESTS.into_response());
                                    }
                                    return Ok(
                                        serde_json::to_string(
                                            &generate_cert(
                                                now,
                                                &req.identity,
                                                &req_params.spki_der,
                                                &state.kms_key_gcpid,
                                                &state.kms_client,
                                            ).await?,
                                        )
                                            .unwrap()
                                            .into_response(),
                                    );
                                },
                            }
                        };
                        match inner.await {
                            Ok(r) => return r,
                            Err(e) => {
                                state.log.log_err(WARN, e.context("Error processing cert request"));
                                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                            },
                        }
                    }

                    ep
                })).with(AddData::new(State(Arc::new(State_ {
                    log: log.fork(ea!(sys = "http")),
                    kms_key_gcpid: config.key_gcpid,
                    kms_client: kms_client,
                    ip_limit: RateLimiter::keyed(
                        Quota::with_period(Duration::hours(24).to_std().unwrap())
                            .unwrap()
                            .allow_burst(NonZeroU32::new(10).unwrap()),
                    ),
                    ident_limit: RateLimiter::keyed(
                        Quota::with_period(Duration::hours(24).to_std().unwrap())
                            .unwrap()
                            .allow_burst(NonZeroU32::new(10).unwrap()),
                    ),
                })))))).await {
                    Some(r) => {
                        return r.stack_context(&log, "Exited with error");
                    },
                    None => {
                        return Ok(());
                    },
                }
            }
        });
        tm.join().await?;
        return Ok(());
    }

    match inner().await {
        Ok(_) => { },
        Err(e) => {
            loga::fatal(e);
        },
    }
}
