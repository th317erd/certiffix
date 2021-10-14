# Certiffix

Generate development certificates using self-signed CA root certificates. This command will assist you in generating self-signed Certificate Authorities. These can then be used to sign certificate requests. You can then have your browser or system trust these generated authorities, and then all certificates signed by them will be considered valid.

On unix based systems it stores the certificates it generates in `~/.config/certiffix/`

**Usage:**

`certiffix {options}`

<hr>
<br>

**Commands:**<br>
|Command|Purpose|
|----|----|
|`certiffix --ca` | Generate a self-signed CA Root Certificate.
|`certiffix`      | Generate a certificate signed by the specified (selectable) CA Root Certificate.

<hr>
<br>

**Arguments:**<br>
*Note: All arguments are optional. If not specified, the command will prompt for needed values.*
| Argument         | Purpose           |
|------------------|-------------------|
|`--ca`             | If specified without a value, a CA Root Certificate will be generated.<br>If specified with a value, then the value should be the path to a CA Root Certificate.
|`--commonName`,<br>`--domain`<br>`--cn`<br>`--common` | Domain name to use for certificate. If prefixed with a `*.`, then a wildcard certificate<br>will be generated.
|`--country`<br>`--c` | Country code value to use for the certificate.
|`--county`<br>`--locality`<br>`--l` | County/Locality value to use for the certificate.
|`--days` | Number of days that this certificate is valid.<br>Default = `398`
|`--email` | Email address value to use for the certificate.
|`--ip` | IP Addresses to use for EXT data in certificate.<br>Can be specified multiple times for multiple IP addresses.<br>Default = `127.0.0.1`
|`--organization`<br>`--org`<br>`--o` | Organization value to use for the certificate.
|`--state`<br>`--st` | State code value to use for the certificate.
|`--unit`<br>`--ou` | Unit value to use for the certificate.
|`--wildcard`<br>`--wild` | If given, then the certificate will be generated as a wildcard certificate.

