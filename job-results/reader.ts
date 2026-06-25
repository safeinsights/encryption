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
    private readonly additionalKeys: Record<string, string>
    private decoded = false

    /**
     * @param additionalKeys inner file path -> AES key wrapped for *this* `fingerprint`. Lets a
     *   recipient absent from the original manifest (e.g. a researcher granted access later)
     *   decrypt the same ciphertext: on decode these are spliced into the manifest under
     *   `fingerprint`, so reads stay a single fingerprint lookup with no bypass.
     */
    constructor(
        zipBlob: Blob,
        privateKey: ArrayBuffer,
        fingerprint: string,
        additionalKeys: Record<string, string> = {},
    ) {
        this.zipReader = new ZipReader(new BlobReader(zipBlob))
        this.fingerprint = fingerprint
        this.privateKey = privateKey
        this.additionalKeys = additionalKeys
    }

    async extractFiles(): Promise<FileEntry[]> {
        const entries = await this.extractFilesWithKeys()
        return entries.map(({ path, contents }) => ({ path, contents }))
    }

    /** Like {@link extractFiles}, but also returns each file's raw AES key for re-wrapping. */
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
        let manifestFound = false
        for (const entry of entries) {
            if (!entry.directory && entry.filename === 'manifest.json') {
                const manifestText = await entry.getData(new TextWriter())
                this.manifest = JSON.parse(manifestText) as ResultsManifest
                manifestFound = true
            }
        }

        if (!manifestFound) {
            throw new Error('Manifest not found in zip archive.')
        }

        // Splice any caller-supplied keys into the manifest under our fingerprint, so a recipient
        // not baked into the zip (e.g. a researcher) reads through the same path as everyone else.
        for (const [path, crypt] of Object.entries(this.additionalKeys)) {
            const file = this.manifest.files[path]
            if (file) file.keys[this.fingerprint] = { crypt }
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

        const crypt = fileEntry.keys[this.fingerprint]?.crypt
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
