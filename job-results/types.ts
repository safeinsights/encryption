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
    algo: 'AES-GCM' // symmetric cipher used for the file body
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
