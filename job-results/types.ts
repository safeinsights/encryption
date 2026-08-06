export type AuditRole = 'admin' | 'researcher' | 'member'

type ResultsFileKey = string

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
