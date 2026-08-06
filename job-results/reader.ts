import { BlobReader, BlobWriter, TextWriter, ZipReader } from '@zip.js/zip.js'
import type { FileEntry as ZipFileEntry } from '@zip.js/zip.js'
import type { ResultsFile, ResultsManifest, FileEntry, FileInfo, ReconciliationReport } from './types'
import { decryptFileBody, unwrapAesKey } from './crypto'
import logger from '../lib/logger'

export type DecryptedEntry = FileEntry & { rawAesKey: ArrayBuffer }

const MANIFEST_FILENAME = 'manifest.json'

/** Raised when the manifest and the zip disagree. Carries the report where one could be built. */
export class ResultsIntegrityError extends Error {
    constructor(
        message: string,
        readonly report?: ReconciliationReport,
    ) {
        super(message)
        this.name = 'ResultsIntegrityError'
    }
}

export type ReadOptions = {
    /** Read the files that did reconcile instead of throwing. Inspect reconcile() for what was lost. */
    partial?: boolean
}

export class ResultsReader {
    manifest: ResultsManifest = {
        files: {},
    }

    private zipReader: ZipReader<Blob>
    private fingerprint: string
    private privateKey: ArrayBuffer
    private readonly additionalKeys: Record<string, string>
    private decoded = false
    private reconciliation?: ReconciliationReport
    /** manifest key -> the zip entry name it resolves to; only holds entries that exist in both */
    private readonly resolvedNames = new Map<string, string>()

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

    async extractFiles(options: ReadOptions = {}): Promise<FileEntry[]> {
        const entries = await this.extractFilesWithKeys(options)
        return entries.map(({ path, contents }) => ({ path, contents }))
    }

    /** Like {@link extractFiles}, but also returns each file's raw AES key for re-wrapping. */
    async extractFilesWithKeys(options: ReadOptions = {}): Promise<DecryptedEntry[]> {
        logger.info(`Extracting files`)

        await this.decode()

        const entries: DecryptedEntry[] = []
        for await (const entry of this.entries(options)) {
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

    /**
     * List what a read would actually yield. Reported names are the reconciled (zip) names, so this
     * cannot advertise a file extractFiles would not hand back — the two disagreed before.
     */
    async listFiles(options: ReadOptions = {}): Promise<FileInfo[]> {
        if (options.partial) {
            await this.reconcile()
        } else {
            await this.assertReconciled()
        }

        const listed: FileInfo[] = []
        for (const [manifestKey, zipName] of this.resolvedNames) {
            const file = this.manifest.files[manifestKey]
            if (file) listed.push({ path: zipName, bytes: file.bytes })
        }
        return listed
    }

    /**
     * Check every manifest entry against the zip's actual contents, and vice versa. Reads went
     * through the *intersection* of the two, so any drift — stray whitespace, or a manifest entry
     * dropped by a hostile store — made files disappear with no error and no count mismatch.
     *
     * Memoized. Throws only when drift cannot be resolved at all (two keys claiming one entry);
     * everything else is reported so the caller decides.
     */
    async reconcile(): Promise<ReconciliationReport> {
        if (this.reconciliation) return this.reconciliation

        await this.decode()
        this.resolvedNames.clear() // a prior call may have thrown partway through

        const zipNames = new Set<string>()
        for (const entry of await this.zipReader.getEntries()) {
            if (!entry.directory && entry.filename !== MANIFEST_FILENAME) zipNames.add(entry.filename)
        }

        const matched: string[] = []
        const missingFromZip: string[] = []
        const normalized: { manifestKey: string; zipName: string }[] = []
        const claimedBy = new Map<string, string>() // zip name -> the manifest key that took it

        for (const manifestKey of Object.keys(this.manifest.files)) {
            // fall back to the trimmed key so archives written before the writer was fixed, whose
            // keys kept whitespace that zip.js had already stripped, still read
            const zipName = zipNames.has(manifestKey)
                ? manifestKey
                : zipNames.has(manifestKey.trim())
                  ? manifestKey.trim()
                  : undefined

            if (zipName === undefined) {
                missingFromZip.push(manifestKey)
                continue
            }

            const priorKey = claimedBy.get(zipName)
            if (priorKey !== undefined) {
                throw new ResultsIntegrityError(
                    `Ambiguous manifest: ${JSON.stringify(priorKey)} and ${JSON.stringify(manifestKey)} ` +
                        `both resolve to zip entry ${JSON.stringify(zipName)}`,
                )
            }

            claimedBy.set(zipName, manifestKey)
            this.resolvedNames.set(manifestKey, zipName)
            matched.push(zipName)
            if (zipName !== manifestKey) normalized.push({ manifestKey, zipName })
        }

        this.reconciliation = {
            matched,
            missingFromZip,
            extraInZip: [...zipNames].filter((name) => !claimedBy.has(name)),
            normalized,
        }
        return this.reconciliation
    }

    /** Reconcile, and refuse to read at all if anything is missing or unaccounted for. */
    private async assertReconciled(): Promise<void> {
        const report = await this.reconcile()
        const problems = [
            report.missingFromZip.length && `missing from zip archive: ${report.missingFromZip.join(', ')}`,
            report.extraInZip.length && `not listed in manifest: ${report.extraInZip.join(', ')}`,
        ].filter((problem) => typeof problem === 'string')

        if (problems.length) {
            throw new ResultsIntegrityError(`Archive does not match its manifest — ${problems.join('; ')}`, report)
        }
    }

    async extractFile(filePath: string): Promise<FileEntry> {
        await this.reconcile()

        const manifestKey = this.manifest.files[filePath]
            ? filePath
            : [...this.resolvedNames].find(([, zipName]) => zipName === filePath.trim())?.[0]
        const file = manifestKey === undefined ? undefined : this.manifest.files[manifestKey]
        if (manifestKey === undefined || !file) {
            throw new Error(`File not found in manifest: ${filePath}`)
        }

        const zipName = this.resolvedNames.get(manifestKey)
        const entries = await this.zipReader.getEntries()
        const entry = zipName === undefined ? undefined : entries.find((e) => e.filename === zipName)
        if (zipName === undefined || !entry || entry.directory) {
            throw new Error(`File not found in zip archive: ${filePath}`)
        }

        const { contents } = await this.readFile(file, entry)
        return { path: zipName, contents }
    }

    async *entries(options: ReadOptions = {}): AsyncGenerator<ResultsFile & DecryptedEntry, void, void> {
        if (options.partial) {
            await this.reconcile()
        } else {
            await this.assertReconciled()
        }

        const byName = new Map((await this.zipReader.getEntries()).map((e) => [e.filename, e]))

        // drive from the manifest, not the zip: a zip entry with no manifest entry has no key or IV
        // and cannot be decrypted, so iterating the zip is what let manifest drift go unnoticed
        for (const [manifestKey, zipName] of this.resolvedNames) {
            const file = this.manifest.files[manifestKey]
            const entry = byName.get(zipName)
            if (!file || !entry || entry.directory) continue

            const { contents, rawAesKey } = await this.readFile(file, entry)
            yield { ...file, path: zipName, contents, rawAesKey }
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
