# Certipasta

There's no decentralized way to distribute TLS certs right now. This is a stop-gap until browsers support certs via Spaghettinuum natively, via plugins, or provide some other mechanism for non-centralized certificate distribution.

Certipasta is like Let's Encrypt but for Spaghettinuum `.s` domains. And you can get a cert in a single HTTP request - no multi-step validation process!

# Browsing the web with root certificates

In order to view websites certified by certipasta you'll need to install the root certificates on your system.

The certificates are restricted to the `.s` top level domain.

You can find the latest active cert bundle at <https://storage.googleapis.com/zlr7wmbe6/spaghettinuum_s.crt>. The certificates last for roughly two years, and are rotated once a year by the repository pipeline in early January - there's one year before the new certificate becomes active and the previous is no longer used to issue certificates.

## Installing root certificates on Linux

1. Add the root cert to the p11-kit-managed store by running:

   ```
   sudo trust anchor --store spaghettinuum_s.crt
   ```

   The file can be used to remove it again later, so you may want to keep it around (it would be nice if this were declarative).

2. Regenerate the legacy certificates other programs still use from the p11-kit store:

   ```
   sudo update-ca-trust
   ```

3. Restart any programes (ex: Firefox, Chrome) that may be using TLS.

### Updating the root certificates

Remove the old cert first:

1. Look up the cert with `trust list` and searching for `certipasta`

2. Copy the first line that starts with `pkcs11:id=`

3. Run `sudo trust anchor --remove 'pkcs11:id=...'` to uninstall the old cert

Then install the new certificate as new.

## Installing root certificates on Windows

1. Add the root cert on the command line with:

   ```
   certutil -addstore root spaghettinuum_s.crt
   ```

## Test the root certificate

You'll need to [set up Spaghettinuum DNS](https://github.com/andrewbaxter/spaghettinuum/blob/master/readme/guide_browse.md) first.

Run `curl https://yryyyyyyydz6tr57fdinhaaxb6okim5ihq6wiy6xagpckx7ekgwz3hsurcohs.s/health`

# Issuing leaf certificates for your site

Requests for certificates are signed by a Spaghettinuum identity and are issued for that identity's `.s` domain, so no other validation is required. [`spagh-auto`](https://github.com/andrewbaxter/spaghettinuum) automates this.

Using a config like this:

```json
{
  "global_addrs": [
    {
      "fixed": "2001:db8::"
    },
    {
      "from_interface": {
        "ip_version": "v6",
        "name": "eth0"
      }
    },
    {
      "lookup": {
        "contact_ip_ver": "v6",
        "lookup": "whatismyip.example.org"
      }
    }
  ],
  "identity": {
    "local": "./my.ident"
  },
  "publisher": "https://yryyyyyyyyei1n3eqbew6ysyy6ocdzseit6j5a6kmwb7s8puxmpcwmingf67r.s",
  "serve": {
    "cert_dir": "/var/spagh/certs"
  }
}
```

run

```
$ spagh-auto --config ./config.json
```

This will request and write certs to `cert_dir`, replacing them before they expire.

Or you can use `spaghettinuum` as a library with `spaghettinuum::self_tls::request_cert`.

Note that there are certificate request rate limits per identity and ip.

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

Methods for intercepting IP traffic is not specific to this service.
