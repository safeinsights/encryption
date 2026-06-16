import { ZipWriter, BlobWriter, TextReader, BlobReader } from '@zip.js/zip.js'

import type { ResultsManifest, PublicKey, FileKeyMap } from './types'
import { wrapAesKey, AES_ALGORITHM } from './crypto'
import logger from '../lib/logger'

export class ResultsWriter {
    zipBlobWriter = new BlobWriter('application/zip')
    zip = new ZipWriter(this.zipBlobWriter)
    manifest: ResultsManifest = {
        files: {},
    }

    constructor(public publicKeys: PublicKey[]) {}

    async addFile(fileName: string, content: ArrayBuffer) {
        logger.info(`Adding file ${fileName} to manifest`)

        // Generate AES key
        const aesKey = await crypto.subtle.generateKey({ name: AES_ALGORITHM, length: 256 }, true, ['encrypt'])

        // Generate random IV (96-bit, the recommended size for AES-GCM)
        const iv = crypto.getRandomValues(new Uint8Array(12))

        // Encrypt content (ciphertext carries the GCM authentication tag)
        const encryptedData = await crypto.subtle.encrypt({ name: AES_ALGORITHM, iv }, aesKey, content)

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
            algo: AES_ALGORITHM,
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
