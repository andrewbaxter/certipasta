# Certipasta

In a world ruled by [not evil corporations](https://bugs.chromium.org/p/chromium/issues/detail?id=914519), with [their puppet organizations](https://bugzilla.mozilla.org/show_bug.cgi?id=1450674) opposing decentralization at every corner, how is a pitiable surf to seek enfranchisement?

That's right, with an alternate TLS root that supports [the Spaghettinuum](https://github.com/andrewbaxter/spaghettinuum)!

Certipasta is like Let's Encrypt but for Spaghettinuum `.s` domains.

# Browsing the web with root certificates

In order to view websites certified by certipasta you'll need to install the root certificates on your system.

The certificates are restricted to the `.s` top level domain.

You can find the latest set of certificates in the build artifacts. The certs last for roughly two years, and are rotated once a year by the repository pipeline.

In most browsers if you download the certificate you'll be prompted to install it, although if package managers package such that it gets installed using normal procedures updated along with operating system updates that would be ideal.

# Issuing leaf certificates for your site

Requests for certificates are signed by a Spaghettinuum identity and are issued for that identity's `.s` domain, so no other validation is required. [`spagh-cli`](https://github.com/andrewbaxter/spaghettinuum) provides a command for this:

```
$ spagh-cli --debug issue-cert local ./my_ident
{
  "cert_priv_pem": "-----BEGIN PRIVATE KEY-----\ZZZZZZZ\n-----END PRIVATE KEY-----\n",
  "cert_pub_pem": "-----BEGIN CERTIFICATE-----\YYYYYYYYYY\n-----END CERTIFICATE-----\n",
  "expires_at": "2024-01-06T05:11:04+00:00"
}
```

(using a local/file-based identity)

or using `spaghettinuum` as a library with `spaghettinuum::self_tls::request_cert`. You can look at `spagh-cli` code for reference on generating a private certificate and SPKI info build the request.

# Security

In order for a malicious entity to compromise an identity domain they'd need to both generate their own certificate for the domain and intercept traffic for the domain.

## Forging certificates

Root certificates are restricted to `.s` domains, so if a certificate is forged it should not be possible to hijack non-Spaghettinuum traffic. All root certificates are generated in a Github pipeline. Generated certificates are displayed in the job, so each certificate in the bundle can be traced to a run of the pipeline and from that to a commit in the repository.

The signing keys are managed by Google Cloud KMS which doesn't allow exporting the private key, so outside of compromising Google there's no way to access that.

Anyone with credentials to the Google Cloud project with sufficient privileges could sign their own certificates. The Google Cloud credentials are stored encrypted with a hardware token on my computer in a password manager, in the local Terraform state file, and in the Github pipeline secrets.

## Intercepting traffic

There are two ways to intercept traffic:

- Publish a false DNS record so that traffic goes to a malicious server
- Take over traffic to the correct server

All Spaghettinuum DNS lookups are signed by the identity, so there's no way to forge a record without compromising the identity itself. An attacker could repeat a previously published record with an address the owner no longer controls, but as long as a newer record exists the network should reject this.

Intercepting IP traffic is not specific to this usage and out of scope.
