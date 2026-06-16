import { BlobReader, BlobWriter, TextWriter, ZipReader } from '@zip.js/zip.js'
import type { FileEntry as ZipFileEntry } from '@zip.js/zip.js'
import type { ResultsFile, ResultsManifest, FileEntry, FileInfo } from './types'
import { decryptFileBody, unwrapAesKey } from './crypto'
import logger from '../lib/logger'

export type DecryptedEntry = FileEntry & { rawAesKey: ArrayBuffer }

export class ResultsReader {
    manifest: ResultsManifest = {
        files: {},
    }

    private zipReader: ZipReader<Blob>
    private fingerprint: string
    private privateKey: ArrayBuffer
    private overrideKeys: Record<string, string>
    private decoded = false

    /**
     * @param overrideKeys optional map of inner file path -> wrapped AES key (`crypt`).
     *   When a path has an override, that crypt is unwrapped with `privateKey` instead
     *   of looking up `fingerprint` in the embedded manifest. This lets a recipient who
     *   was NOT an original manifest key holder (e.g. a researcher granted access at
     *   approval time) decrypt the same ciphertext using their own re-wrapped key.
     */
    constructor(
        zipBlob: Blob,
        privateKey: ArrayBuffer,
        fingerprint: string,
        overrideKeys: Record<string, string> = {},
    ) {
        this.zipReader = new ZipReader(new BlobReader(zipBlob))
        this.fingerprint = fingerprint
        this.privateKey = privateKey
        this.overrideKeys = overrideKeys
    }

    async extractFiles(): Promise<FileEntry[]> {
        const entries = await this.extractFilesWithKeys()
        return entries.map(({ path, contents }) => ({ path, contents }))
    }

    /**
     * Like {@link extractFiles}, but also returns each file's raw AES key. The
     * reviewer's browser uses these to re-wrap keys for researchers at approve
     * time without decrypting a second time.
     */
    async extractFilesWithKeys(): Promise<DecryptedEntry[]> {
        logger.info(`Extracting files`)

        await this.decode()

        const entries: DecryptedEntry[] = []
        for await (const entry of this.entries()) {
            entries.push({
                path: entry.path,
                contents: entry.contents,
                rawAesKey: entry.rawAesKey,
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

        const { contents } = await this.readFile(file, entry)
        return { path: filePath, contents }
    }

    async *entries(): AsyncGenerator<ResultsFile & DecryptedEntry, void, void> {
        const entries = await this.zipReader.getEntries()
        for (const entry of entries) {
            const file = this.manifest.files[entry.filename]
            if (!entry.directory && file) {
                const { contents, rawAesKey } = await this.readFile(file, entry)
                yield { ...file, contents, rawAesKey }
            }
        }
    }

    private async readFile(
        fileEntry: ResultsFile,
        entry: ZipFileEntry,
    ): Promise<{ contents: ArrayBuffer; rawAesKey: ArrayBuffer }> {
        logger.info(`Reading file ${entry.filename}`)

        const encryptedData = await entry.getData(new BlobWriter())

        const crypt = this.overrideKeys[entry.filename] ?? fileEntry.keys[this.fingerprint]?.crypt
        if (!crypt) throw new Error(`file was not encrypted with key signature ${this.fingerprint}`)

        const { aesKey, rawAesKey } = await unwrapAesKey(crypt, this.privateKey)

        logger.info(`Finished reading file ${entry.filename}`)
        const contents = await decryptFileBody(
            await encryptedData.arrayBuffer(),
            Buffer.from(fileEntry.iv, 'base64'),
            aesKey,
        )
        return { contents, rawAesKey }
    }
}
