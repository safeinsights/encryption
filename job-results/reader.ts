import { BlobReader, BlobWriter, TextWriter, ZipReader } from '@zip.js/zip.js'
import type { FileEntry as ZipFileEntry } from '@zip.js/zip.js'
import type { ResultsFile, ResultsManifest, FileEntry, FileInfo } from './types'
import { privateKeyFromBufferForUnwrap } from '../util'
import logger from '../lib/logger'

export class ResultsReader {
    manifest: ResultsManifest = {
        files: {},
    }

    private zipReader: ZipReader<Blob>
    private fingerprint: string
    private privateKey: ArrayBuffer | CryptoKey
    private importedKey?: CryptoKey
    private decoded = false

    /**
     * Construct a reader from a pre-imported `CryptoKey`.
     *
     * The `CryptoKey` must have been imported with `keyUsages: ['unwrapKey']`
     * (RSA-OAEP, SHA-256). It may be (and is recommended to be) non-extractable,
     * so raw key bytes never reside in JS memory.
     *
     * @param fingerprint  SHA-256 hex of the SPKI public key. Required — it
     *   cannot be derived from a non-extractable key.
     */
    constructor(zipBlob: Blob, privateKey: CryptoKey, fingerprint: string)
    /**
     * @deprecated Pass a `CryptoKey` instead so raw key bytes do not have to
     *   live in JS memory. Import as:
     *   `crypto.subtle.importKey('pkcs8', bytes, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['unwrapKey'])`.
     */
    constructor(zipBlob: Blob, privateKey: ArrayBuffer, fingerprint: string)
    constructor(zipBlob: Blob, privateKey: ArrayBuffer | CryptoKey, fingerprint: string) {
        if (privateKey instanceof CryptoKey && !privateKey.usages.includes('unwrapKey')) {
            throw new Error(
                `ResultsReader: CryptoKey must be imported with usages: ['unwrapKey'] (got: ${JSON.stringify(privateKey.usages)})`,
            )
        }
        this.zipReader = new ZipReader(new BlobReader(zipBlob))
        this.fingerprint = fingerprint
        this.privateKey = privateKey
    }

    private async getPrivateKey(): Promise<CryptoKey> {
        if (this.privateKey instanceof CryptoKey) return this.privateKey
        if (!this.importedKey) {
            this.importedKey = await privateKeyFromBufferForUnwrap(this.privateKey)
        }
        return this.importedKey
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
        if (this.decoded) return

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

        this.decoded = true
        logger.info(`Finished decoding entries`)
    }

    async listFiles(): Promise<FileInfo[]> {
        await this.decode()
        return Object.values(this.manifest.files).map(({ path, bytes }) => ({ path, bytes }))
    }

    async extractFile(filePath: string): Promise<FileEntry> {
        await this.decode()

        const file = this.manifest.files[filePath]
        if (!file) {
            throw new Error(`File not found in manifest: ${filePath}`)
        }

        const entries = await this.zipReader.getEntries()
        const entry = entries.find((e) => !e.directory && e.filename === filePath)
        if (!entry || entry.directory) {
            throw new Error(`File not found in zip archive: ${filePath}`)
        }

        const contents = await this.readFile(file, entry)
        return { path: filePath, contents }
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

        const key = await crypto.subtle.unwrapKey(
            'raw',
            encryptedKey,
            await this.getPrivateKey(),
            { name: 'RSA-OAEP' },
            { name: 'AES-CBC', length: 256 },
            false,
            ['decrypt'],
        )

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
