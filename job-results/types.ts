export type AuditRole = 'admin' | 'researcher' | 'member'

type ResultsFileKey = string

/**
 * Symmetric ciphers a manifest may declare for its file bodies.
 *
 * `AES-CBC` is the legacy, *unauthenticated* format written before the manifest carried a cipher
 * field. It is read-only: the writer never emits it again. `AES-GCM` is authenticated (AEAD) and
 * binds each body to its job and path — see {@link fileAdditionalData}.
 */
export type CipherName = 'AES-CBC' | 'AES-GCM'

export type PublicKey = {
    fingerprint: string // sha 256 fingerprint of members public key
    publicKey: ArrayBuffer
}

export type FileKeyMap = {
    [fingerprint: string]: {
        crypt: string // encrypted version of the AES symmetric key used to encrypt file
    }
}

export type ResultsFile = {
    path: string
    bytes: number // size of the file in bytes BEFORE encryption
    iv: string // initialization vector for encryption, should be unique for each file
    keys: FileKeyMap // mapping of key fingerprint <-> encrypted AES key
}

export type ResultsManifest = {
    /**
     * Manifest format version. Absent means version 1 — the original format, which predates both
     * this field and {@link ResultsManifest.cipher} and is therefore AES-CBC.
     */
    version?: number
    /** Cipher used for every file body in this archive. Absent means legacy `AES-CBC`. */
    cipher?: CipherName
    /**
     * Job this archive belongs to, bound into every file body's AAD under AES-GCM.
     *
     * Untrusted on its own — a hostile store can rewrite it, and rewriting it invalidates every
     * body in the archive rather than just one, which is the point. A reader that knows the job it
     * asked for should pass `jobId` in {@link ReadOptions} so the two are checked against each
     * other; see `ResultsReader`.
     */
    jobId?: string
    files: Record<ResultsFileKey, ResultsFile> // key is the path of the file
}

export type FileEntry = {
    path: string
    contents: ArrayBuffer
}

export type FileInfo = {
    path: string
    bytes: number // original (pre-encryption) file size
}

/** Outcome of checking the manifest against the zip's actual entries. */
export type ReconciliationReport = {
    matched: string[] // canonical (zip) names that resolved cleanly — what a read yields
    missingFromZip: string[] // manifest keys with no zip entry: lost data, or an adversarial drop
    extraInZip: string[] // zip entries absent from the manifest, so undecryptable
    normalized: { manifestKey: string; zipName: string }[] // matched only after trimming
}
