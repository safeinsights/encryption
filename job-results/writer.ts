import { ZipWriter, BlobWriter, TextReader, BlobReader } from '@zip.js/zip.js'

import type { ResultsManifest, PublicKey, FileKeyMap } from './types'

export class ResultsWriter {
    zipBlobWriter = new BlobWriter('application/zip')
    zip = new ZipWriter(this.zipBlobWriter)
    manifest: ResultsManifest = {
        files: {},
    }

    constructor(public publicKeys: PublicKey[]) {}

    async addFile(fileName: string, content: ArrayBuffer) {
        // Generate AES key
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
                crypt: await this.encryptAesKeyWithPublicKey(key, rawAesKey),
            }
        }

        await this.zip.add(fileName, new BlobReader(new Blob([encryptedData])))

        this.manifest.files[fileName] = {
            path: fileName,
            bytes: content.byteLength, // n.b. size BEFORE encryption
            keys,
            iv: Buffer.from(iv).toString('base64'),
        }
    }

    async generate(): Promise<Blob> {
        await this.zip.add('manifest.json', new TextReader(JSON.stringify(this.manifest)))
        await this.zip.close()

        return this.zipBlobWriter.getData()
    }

    private async encryptAesKeyWithPublicKey(key: PublicKey, aesKey: ArrayBuffer): Promise<string> {
        // Decode the public key
        const publicKey = await crypto.subtle.importKey(
            'spki',
            key.publicKey,
            {
                name: 'RSA-OAEP',
                hash: 'SHA-256',
            },
            false,
            ['encrypt'],
        )

        // Encrypt the AES key
        const encryptedKey = await crypto.subtle.encrypt(
            {
                name: 'RSA-OAEP',
            },
            publicKey,
            aesKey,
        )

        return Buffer.from(encryptedKey).toString('base64')
    }
}
