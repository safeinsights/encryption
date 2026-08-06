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

        // zip.js trims entry names on add, so storing the raw name as the manifest key let the two
        // disagree and the file vanished from reads. Derive both from one trimmed value instead.
        const name = fileName.trim()
        if (!name) {
            throw new Error(`Invalid filename ${JSON.stringify(fileName)}: empty once trimmed`)
        }
        if (this.manifest.files[name]) {
            throw new Error(`Duplicate filename ${JSON.stringify(name)} already added`)
        }

        logger.info(`Adding file ${name} to manifest`)

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

        await this.zip.add(name, new BlobReader(new Blob([encryptedData])))

        this.manifest.files[name] = {
            path: name,
            bytes: content.byteLength, // n.b. size BEFORE encryption
            keys,
            iv: Buffer.from(iv).toString('base64'),
        }
        logger.info(`Finished adding file ${name} to manifest`)
    }

    async generate(): Promise<Blob> {
        logger.info(`Adding manifest.json to zip`)

        await this.zip.add('manifest.json', new TextReader(JSON.stringify(this.manifest)))
        await this.zip.close()

        logger.info(`Finished adding manifest.json to zip`)
        return this.zipBlobWriter.getData()
    }
}
