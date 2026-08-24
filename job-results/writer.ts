import { ZipWriter, BlobWriter, TextReader, BlobReader } from '@zip.js/zip.js'

import type { ResultsManifest, PublicKey, FileKeyMap } from './types'
import {
    wrapAesKey,
    encryptFileBody,
    fileAdditionalData,
    CURRENT_CIPHER,
    GCM_IV_BYTES,
    MANIFEST_VERSION,
} from './crypto'
import logger from '../lib/logger'

// The AES key is discarded once wrapped for each recipient, so a file written with no recipients
// is permanently undecryptable — and the zip still looks valid. Fail loudly instead.
function assertHasRecipients(publicKeys: PublicKey[]) {
    if (!publicKeys?.length) {
        throw new Error('ResultsWriter requires at least one recipient public key')
    }
}

export type WriteOptions = {
    /**
     * Job these results belong to. Bound into every file body's AAD and recorded in the manifest,
     * so a body cannot be spliced into another job's archive undetected.
     *
     * Optional only because not every caller has one to hand; supply it whenever you do. Without
     * it bodies are still bound to their path, but nothing ties the archive to a job.
     */
    jobId?: string
}

export class ResultsWriter {
    zipBlobWriter = new BlobWriter('application/zip')
    zip = new ZipWriter(this.zipBlobWriter)
    manifest: ResultsManifest = {
        version: MANIFEST_VERSION,
        cipher: CURRENT_CIPHER,
        files: {},
    }

    /** Bound into every AAD. Held separately so mutating the public manifest cannot desynchronise
     * files added before and after the change — such an archive fails to read rather than reading
     * back partially. */
    private readonly jobId?: string

    constructor(
        public publicKeys: PublicKey[],
        options: WriteOptions = {},
    ) {
        assertHasRecipients(publicKeys)

        if (options.jobId !== undefined) {
            if (!options.jobId.trim()) {
                throw new Error('ResultsWriter jobId must be a non-empty string when supplied')
            }
            this.jobId = options.jobId
            this.manifest.jobId = options.jobId
        }
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

        const aesKey = await crypto.subtle.generateKey({ name: CURRENT_CIPHER, length: 256 }, true, ['encrypt'])
        const iv = crypto.getRandomValues(new Uint8Array(GCM_IV_BYTES))

        // AAD binds the body to this archive's job and this entry's name. `name` is what lands in
        // the zip, so the reader can rebuild the same AAD from the entry it actually read.
        const encryptedData = await encryptFileBody(content, iv, aesKey, {
            cipher: CURRENT_CIPHER,
            additionalData: fileAdditionalData(this.jobId, name),
        })

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
