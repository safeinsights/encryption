export type AuditRole = 'admin' | 'researcher' | 'member'

type ResultsFileKey = string

export type PublicKey = {
    fingerprint: string // sha 256 fingerprint of members public key
    publicKey: string // PEM encoded RSA public key
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
