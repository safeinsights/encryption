import { ZipReader, Entry, BlobReader, TextWriter, BlobWriter } from '@zip.js/zip.js'
import type { ResultsManifest, ResultsFile } from './types'
import { fingerprintFromPrivateKey, privateKeyFromString } from '../util'

export class ResultsReader {
    manifest: ResultsManifest = {
        files: {},
    }

    private zipReader: ZipReader<Blob>
    publicKeyFingerprint: string
    privateKey: CryptoKey

    async decode(zipBlob: Blob) {
        // this.parseKeys(privateKeyString)

        this.zipReader = new ZipReader(new BlobReader(zipBlob))

        const entries = await this.zipReader.getEntries()
        for (const entry of entries) {
            if (entry.getData && entry.filename == 'manifest.json') {
                const manifestText = await entry.getData(new TextWriter())
                this.manifest = JSON.parse(manifestText) as ResultsManifest
            }
        }
        if (!this.manifest) {
            throw new Error('Manifest not found in zip archive.')
        }

        return this
    }

    async *entries(): AsyncGenerator<ResultsFile & { contents: ArrayBuffer }, void, void> {
        const entries = await this.zipReader.getEntries()
        for (const entry of entries) {
            const file = this.manifest.files[entry.filename]
            if (entry.getData && file) {
                const contents = await this.readFile(file, entry)
                yield { ...file, contents }
            }
        }
    }

    async readFile(fileEntry: ResultsFile, entry: Entry): Promise<ArrayBuffer> {
        if (!entry.getData) {
            throw new Error('Entry does not have data')
        }

        const encryptedData = await entry.getData(new BlobWriter())

        const encryptionKey = fileEntry.keys[this.publicKeyFingerprint]
        if (!encryptionKey) throw new Error(`file was not encrypted with key signature ${this.publicKeyFingerprint}`)

        const aesKey = await this.decryptKeyWithPrivateKey(encryptionKey.crypt)

        const iv = Uint8Array.from(Buffer.from(fileEntry.iv, 'base64'))
        return this.decryptData(encryptedData, aesKey, iv)
    }

    private async decryptKeyWithPrivateKey(encryptedKeyBase64: string): Promise<CryptoKey> {
        const encryptedKey = Buffer.from(encryptedKeyBase64, 'base64')

        const rawKey = await crypto.subtle.decrypt(
            {
                name: 'RSA-OAEP',
            },
            this.privateKey,
            encryptedKey,
        )

        return await crypto.subtle.importKey('raw', rawKey, { name: 'AES-CBC' }, false, ['decrypt'])
    }

    private async decryptData(encryptedData: Blob, aesKey: CryptoKey, iv: Uint8Array): Promise<ArrayBuffer> {
        const arrayBuffer = await encryptedData.arrayBuffer()
        return crypto.subtle.decrypt(
            {
                name: 'AES-CBC',
                iv,
            },
            aesKey,
            arrayBuffer,
        )
    }

    async parseKeys(privateKeyString: string) {
        this.privateKey = await privateKeyFromString(privateKeyString)
        this.publicKeyFingerprint = await fingerprintFromPrivateKey(this.privateKey)
    }
}
