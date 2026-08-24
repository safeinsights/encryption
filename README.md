# SI encryption

A collection of encryption libraries and functions in use at SafeInsights

## JobResults

The job-results folder contains a reader and writer class for transport of SafeInsights results in an encrypted format. It originally lived in the [experiments
/encrypted-results](https://github.com/safeinsights/experiments/tree/main/encrypted-results) repository

### Container format

A results archive is a zip holding one `manifest.json` plus one encrypted body per file. Each body
gets its own AES key, and that key is RSA-OAEP wrapped once per recipient fingerprint.

```jsonc
{
    "version": 2,
    "cipher": "AES-GCM",
    "jobId": "job-4711",
    "files": {
        "result.csv": {
            "path": "result.csv",
            "bytes": 1234, // size BEFORE encryption
            "iv": "…base64, 96-bit…",
            "keys": { "<sha256 fingerprint>": { "crypt": "…base64 RSA-OAEP wrapped AES key…" } },
        },
    },
}
```

| version | cipher    | notes                                                             |
| ------- | --------- | ----------------------------------------------------------------- |
| absent  | absent    | original format; unauthenticated AES-CBC, 128-bit IV. Read-only.  |
| 2       | `AES-GCM` | authenticated, AAD-bound, 96-bit IV. What the writer emits today. |

`ResultsReader` is dual-mode: it reads both, choosing on the manifest's `cipher` field. An
unrecognised `cipher`, or a `version` newer than the build understands, is refused rather than
guessed at.

### What AES-GCM buys, and what it does not

Each body is encrypted with the file's path and the archive's `jobId` as **additional authenticated
data**:

```
AAD = JSON.stringify(["si-encryption/job-results", 1, jobId, path])
```

Decryption fails if any of these were tampered with, so the following are all detected:

- a flipped byte in the ciphertext, or a modified IV;
- a body swapped onto a different path in the same archive;
- a body spliced in from another job for the same recipient;
- a renamed entry, even when the manifest key and the zip entry are renamed together.

Two things this does **not** protect against, both by design of the current stage:

- **Blind forgery.** RSA-OAEP wrapping is a public operation. Anyone holding a recipient's public
  key — which is distributed by design — and able to write to storage can mint a fresh AES key,
  encrypt fabricated content under the correct AAD, wrap the key for that recipient, and produce an
  archive that decrypts with no error. Closing this needs the enclave to **sign** the manifest; the
  AAD binding is what makes such a signature meaningful, not a substitute for it.
- **Downgrade to the legacy format.** While `AES-CBC` archives are still readable, an attacker can
  forge one and it will be accepted, because CBC verifies nothing. Pass
  `requireAuthenticatedCipher: true` to shut that door as soon as no legacy archive can reach the
  reader.

### Usage

```ts
// writing — pass jobId whenever you have one; it is what binds the archive to a job
const writer = new ResultsWriter(recipientPublicKeys, { jobId })
await writer.addFile('result.csv', contents)
const zip = await writer.generate()

// reading — pass the jobId you asked for, from your own records, never from the archive
const reader = new ResultsReader(zip, privateKey, fingerprint, additionalKeys, { jobId })
const files = await reader.extractFiles()
```

`jobId` is optional on both sides so that existing callers and legacy archives keep working, but a
reader that supplies one gets the archive's claim checked against it — which is what catches a whole
archive swapped in from a different job. A reader that supplies none accepts whatever job the
archive claims.
