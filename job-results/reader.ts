import { BlobReader, BlobWriter, FileEntry as ZipFileEntry, TextWriter, ZipReader } from '@zip.js/zip.js'
import type { ResultsFile, ResultsManifest, FileEntry } from './types'
import { privateKeyFromBuffer } from '../util'
import logger from '../lib/logger'

export class ResultsReader {
    manifest: ResultsManifest = {
        files: {},
    }

    private zipReader: ZipReader<Blob>
    private fingerprint: string
    private privateKey: ArrayBuffer

    constructor(zipBlob: Blob, privateKey: ArrayBuffer, fingerprint: string) {
        this.zipReader = new ZipReader(new BlobReader(zipBlob))
        this.fingerprint = fingerprint
        this.privateKey = privateKey
    }

    async extractFiles() {
        logger.info(`Extracting files`)

        await this.decode()

        const generator = this.entries()
        const entries: FileEntry[] = []
        for await (const entry of generator) {
            entries.push({
                path: entry.path,
                contents: entry.contents,
            })
        }
        logger.info(`Finished extracting files`)
        return entries
    }

    async decode() {
        logger.info(`Decoding entries`)

        const entries = await this.zipReader.getEntries()
        for (const entry of entries) {
            if (!entry.directory && entry.filename == 'manifest.json') {
                const manifestText = await entry.getData(new TextWriter())
                this.manifest = JSON.parse(manifestText) as ResultsManifest
            }
        }

        if (!this.manifest) {
            throw new Error('Manifest not found in zip archive.')
        }

        logger.info(`Finished decoding entries`)
    }

    async *entries(): AsyncGenerator<ResultsFile & { contents: ArrayBuffer }, void, void> {
        const entries = await this.zipReader.getEntries()
        for (const entry of entries) {
            const file = this.manifest.files[entry.filename]
            if (!entry.directory && file) {
                const contents = await this.readFile(file, entry)
                yield { ...file, contents }
            }
        }
    }

    private async readFile(fileEntry: ResultsFile, entry: ZipFileEntry): Promise<ArrayBuffer> {
        logger.info(`Reading file ${entry.filename}`)

        const encryptedData = await entry.getData(new BlobWriter())

        const encryptionKey = fileEntry.keys[this.fingerprint]
        if (!encryptionKey) throw new Error(`file was not encrypted with key signature ${this.fingerprint}`)

        const aesKey = await this.decryptKeyWithPrivateKey(encryptionKey.crypt)

        const iv = Buffer.from(fileEntry.iv, 'base64')

        logger.info(`Finished reading file ${entry.filename}`)
        return this.decryptData(encryptedData, aesKey, iv)
    }

    private async decryptKeyWithPrivateKey(encryptedKeyBase64: string): Promise<CryptoKey> {
        logger.info(`Decrypting key`)

        const encryptedKey = Buffer.from(encryptedKeyBase64, 'base64')

        const rawKey = await crypto.subtle.decrypt(
            {
                name: 'RSA-OAEP',
            },
            await privateKeyFromBuffer(this.privateKey),
            encryptedKey,
        )

        const key = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-CBC' }, false, ['decrypt'])

        logger.info(`Finished decrypting key`)

        return key
    }

    private async decryptData(encryptedData: Blob, aesKey: CryptoKey, iv: BufferSource): Promise<ArrayBuffer> {
        logger.info(`Decrypting data`)

        const arrayBuffer = await encryptedData.arrayBuffer()
        const results = crypto.subtle.decrypt(
            {
                name: 'AES-CBC',
                iv,
            },
            aesKey,
            arrayBuffer,
        )

        logger.info(`Finished decrypting data`)

        return results
    }
}
