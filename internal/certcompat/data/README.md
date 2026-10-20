# Android system CA profiles

This directory is an offline snapshot of the AOSP system CA certificates for
22 Android release profiles from 4.1 through 17. `profiles.json` records the
dataset version, exact repository, immutable Git commit, release tag, source
directory and sorted DER SHA-256 fingerprints for each profile. Each unique
certificate appears once in `roots/<DER-SHA256>.pem`, in canonical PEM form.
Only the certificate block is extracted; the AOSP OpenSSL diagnostic text is
not part of the certificate. Uploaded certificates cannot modify these roots.

## Regenerate and verify

From the repository root, using Python 3.10 or later:

```sh
python3 scripts/update_android_truststores.py
python3 scripts/update_android_truststores.py --verify
```

Updating requires access to `https://android.googlesource.com`. Verification
is offline. Downloads use a bounded worker pool, retries and pinned source
commits; both Git blob hashes and DER SHA-256 fingerprints are checked.
No host trust store or alternate release is used as a fallback. Change
`RELEASES` and `DATA_VERSION` deliberately when updating the snapshot. The
updater validates every download before writing the generated dataset.

## Interpretation

These are release baselines, not a model of every device or security update.
For historical versions the selected baseline is Android 4.1.1, 4.2.2, 4.3,
4.4.4 and 5.1.1; other profiles use their first release tag. Android 7.1
and 7.1.1 remain separate release profiles although their pinned root sets
are identical. Since
Android 14, updatable system trust stores can also differ from the release
baseline. OEM changes, user-added CAs and application-specific trust stores
are outside this dataset. Trust-anchor membership alone cannot establish
TLS protocol, cipher, hostname or application compatibility.

Official CA device compatibility tables can differ from these raw AOSP
baselines. For example, [Let's Encrypt's compatibility documentation](https://letsencrypt.org/docs/certificate-compatibility/)
lists ISRG Root X1 support from Android 7.1.1, whereas X1 is already present
in the pinned AOSP Android 7.1 snapshot. Version labels therefore describe
estimated trust against the specified AOSP source snapshot; they do not
guarantee a minimum supported device version. The source data is preserved
exactly rather than changed to match an external compatibility table.

## Source notices and licensing

Source: Android Open Source Project, `platform/libcore` (Android 4.1–6.0)
and `platform/system/ca-certificates` (Android 7.0–17). Exact source links
are recorded per profile in `profiles.json`. The original CA certificates
remain subject to their issuers' applicable terms. They are not asserted
to be covered by Certimate's license or by the license of AOSP code.

`source-notices/` preserves the upstream libcore NOTICE and the modern
CA repository's README and METADATA. In particular, upstream METADATA
marks the CA package as `BY_EXCEPTION_ONLY` and references the QuoVadis
Certificate Holder Agreement; that notice is preserved verbatim.
