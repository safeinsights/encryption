import { ZipWriter, BlobWriter, TextReader, BlobReader } from '@zip.js/zip.js'

import type { ResultsManifest, PublicKey, FileKeyMap } from './types'
import { wrapAesKey } from './crypto'
import logger from '../lib/logger'

// The AES key is discarded once wrapped for each recipient, so a file written with no recipients
// is permanently undecryptable — and the zip still looks valid. Fail loudly instead.
function assertHasRecipients(publicKeys: PublicKey[]) {
    if (!publicKeys?.length) {
        throw new Error('ResultsWriter requires at least one recipient public key')
    }
}

export class ResultsWriter {
    zipBlobWriter = new BlobWriter('application/zip')
    zip = new ZipWriter(this.zipBlobWriter)
    manifest: ResultsManifest = {
        files: {},
    }

    constructor(public publicKeys: PublicKey[]) {
        assertHasRecipients(publicKeys)
    }

    async addFile(fileName: string, content: ArrayBuffer) {
        // re-checked here: publicKeys is public and mutable after construction
        assertHasRecipients(this.publicKeys)

        logger.info(`Adding file ${fileName} to manifest`)

        // AES-CBC (not GCM) for backward-compat: existing production results are CBC-encrypted,
        // and the cipher isn't stamped in the manifest, so switching would orphan that data.
        // NOTE: CBC is unauthenticated — ciphertext/IV integrity is NOT verified on decrypt
        // (SonarQube S5542). Callers must not treat decrypted bodies as tamper-proof.
        const aesKey = await crypto.subtle.generateKey({ name: 'AES-CBC', length: 256 }, true, ['encrypt'])

        // Generate random IV
        const iv = crypto.getRandomValues(new Uint8Array(16))

        // Encrypt content
        const encryptedData = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, aesKey, content)

        // Export AES key as raw bytes
        const rawAesKey = await crypto.subtle.exportKey('raw', aesKey)

        const keys: FileKeyMap = {}
        for (const key of this.publicKeys) {
            keys[key.fingerprint] = {
                crypt: await wrapAesKey(rawAesKey, key.publicKey),
            }
        }

        await this.zip.add(fileName, new BlobReader(new Blob([encryptedData])))

        this.manifest.files[fileName] = {
            path: fileName,
            bytes: content.byteLength, // n.b. size BEFORE encryption
            keys,
            iv: Buffer.from(iv).toString('base64'),
        }
        logger.info(`Finished adding file ${fileName} to manifest`)
    }

    async generate(): Promise<Blob> {
        logger.info(`Adding manifest.json to zip`)

        await this.zip.add('manifest.json', new TextReader(JSON.stringify(this.manifest)))
        await this.zip.close()

        logger.info(`Finished adding manifest.json to zip`)
        return this.zipBlobWriter.getData()
    }
}
