import { BlobReader, BlobWriter, TextWriter, ZipReader } from '@zip.js/zip.js'
import type { FileEntry as ZipFileEntry } from '@zip.js/zip.js'
import type { CipherName, ResultsFile, ResultsManifest, FileEntry, FileInfo, ReconciliationReport } from './types'
import {
    decryptFileBody,
    unwrapAesKey,
    fileAdditionalData,
    CURRENT_CIPHER,
    LEGACY_CIPHER,
    LEGACY_MANIFEST_VERSION,
    MANIFEST_VERSION,
} from './crypto'
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

/**
 * Resolve a manifest key to the zip entry it names.
 *
 * Falls back to the trimmed key so archives written before the writer was fixed — whose keys kept
 * whitespace that zip.js had already stripped from the entry name — still read.
 */
function resolveZipName(manifestKey: string, zipNames: ReadonlySet<string>): string | undefined {
    if (zipNames.has(manifestKey)) return manifestKey

    const trimmed = manifestKey.trim()
    return zipNames.has(trimmed) ? trimmed : undefined
}

export type ReaderOptions = {
    /**
     * The job these results are expected to belong to, known out of band (from the caller's own
     * records — never from the archive). Checked against the manifest, and refused on mismatch,
     * which is what catches a whole archive swapped in from another job.
     */
    jobId?: string
    /**
     * Refuse archives whose bodies are not authenticated, i.e. the legacy `AES-CBC` format.
     *
     * Off by default so production data written before the cipher field still reads. Turn it on
     * once no unauthenticated archive can reach this reader — until then, a hostile store can
     * forge a CBC archive and have it accepted, because CBC verifies nothing.
     */
    requireAuthenticatedCipher?: boolean
}

export class ResultsReader {
    manifest: ResultsManifest = {
        files: {},
    }

    private zipReader: ZipReader<Blob>
    private fingerprint: string
    private privateKey: ArrayBuffer
    private readonly additionalKeys: Record<string, string>
    private readonly options: ReaderOptions
    private decoded = false
    private reconciliation?: ReconciliationReport
    /** manifest key -> the zip entry name it resolves to; only holds entries that exist in both */
    private readonly resolvedNames = new Map<string, string>()

    /**
     * @param additionalKeys inner file path -> AES key wrapped for *this* `fingerprint`. Lets a
     *   recipient absent from the original manifest (e.g. a researcher granted access later)
     *   decrypt the same ciphertext: on decode these are spliced into the manifest under
     *   `fingerprint`, so reads stay a single fingerprint lookup with no bypass.
     * @param options see {@link ReaderOptions}. Pass `jobId` whenever the caller knows which job it
     *   asked for — without it the archive's own claim about its job goes unchecked.
     */
    constructor(
        zipBlob: Blob,
        privateKey: ArrayBuffer,
        fingerprint: string,
        additionalKeys: Record<string, string> = {},
        options: ReaderOptions = {},
    ) {
        this.zipReader = new ZipReader(new BlobReader(zipBlob))
        this.fingerprint = fingerprint
        this.privateKey = privateKey
        this.additionalKeys = additionalKeys
        this.options = options
    }

    /** Cipher this archive's bodies are encrypted with. Only valid after {@link decode}. */
    private get cipher(): CipherName {
        return this.manifest.cipher ?? LEGACY_CIPHER
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

        this.assertManifestSupported()

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
     * Reject a manifest this build cannot read faithfully, before any body is touched.
     *
     * Every branch here fails closed. Reading an unknown format by guessing is exactly how a
     * downgrade slips through: the archive claims something we do not understand, and the honest
     * answer is to refuse rather than to fall back to the weakest thing we do understand.
     */
    private assertManifestSupported(): void {
        const { version = LEGACY_MANIFEST_VERSION, cipher = LEGACY_CIPHER, jobId } = this.manifest

        if (!Number.isInteger(version) || version < LEGACY_MANIFEST_VERSION || version > MANIFEST_VERSION) {
            throw new ResultsIntegrityError(
                `Unsupported manifest version ${JSON.stringify(this.manifest.version)} — ` +
                    `this build reads up to version ${MANIFEST_VERSION}`,
            )
        }

        if (cipher !== CURRENT_CIPHER && cipher !== LEGACY_CIPHER) {
            throw new ResultsIntegrityError(`Unsupported manifest cipher ${JSON.stringify(cipher)}`)
        }

        if (this.options.requireAuthenticatedCipher && cipher !== CURRENT_CIPHER) {
            throw new ResultsIntegrityError(
                `Archive uses unauthenticated cipher ${JSON.stringify(cipher)} but an authenticated one is required`,
            )
        }

        // Only checked when the caller told us which job to expect. A legacy archive carries no
        // jobId to check against, so it is the caller's own records — not this manifest — that
        // decide whether an unbound archive is acceptable at all.
        const expected = this.options.jobId
        if (expected !== undefined && jobId !== undefined && jobId !== expected) {
            throw new ResultsIntegrityError(
                `Archive belongs to job ${JSON.stringify(jobId)}, expected ${JSON.stringify(expected)}`,
            )
        }
        if (expected !== undefined && jobId === undefined && cipher === CURRENT_CIPHER) {
            throw new ResultsIntegrityError(
                `Archive declares no job id, expected ${JSON.stringify(expected)} — refusing to read it as unbound`,
            )
        }
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

        const zipNames = await this.zipEntryNames()

        const matched: string[] = []
        const missingFromZip: string[] = []
        const normalized: { manifestKey: string; zipName: string }[] = []
        const claimedBy = new Map<string, string>() // zip name -> the manifest key that took it

        for (const manifestKey of Object.keys(this.manifest.files)) {
            const zipName = resolveZipName(manifestKey, zipNames)

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

    /** Names of the archive's real file entries — directories and the manifest itself excluded. */
    private async zipEntryNames(): Promise<Set<string>> {
        const names = new Set<string>()
        for (const entry of await this.zipReader.getEntries()) {
            if (!entry.directory && entry.filename !== MANIFEST_FILENAME) names.add(entry.filename)
        }
        return names
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

        const cipher = this.cipher
        const { aesKey, rawAesKey } = await unwrapAesKey(crypt, this.privateKey, cipher)

        logger.info(`Finished reading file ${entry.filename}`)
        // AAD is rebuilt from the zip entry name — the same value the writer bound — so a renamed
        // entry, a body moved between paths, or a splice from another job fails the tag check.
        const contents = await decryptFileBody(
            await encryptedData.arrayBuffer(),
            Buffer.from(fileEntry.iv, 'base64'),
            aesKey,
            {
                cipher,
                additionalData:
                    cipher === CURRENT_CIPHER ? fileAdditionalData(this.manifest.jobId, entry.filename) : undefined,
            },
        )
        return { contents, rawAesKey }
    }
}
