import { ZipReader, ZipWriter, BlobReader, BlobWriter, TextWriter, TextReader } from '@zip.js/zip.js'
import type { ResultsManifest } from '../job-results/types'

export const MANIFEST_FILENAME = 'manifest.json'

/** One decrypted-at-rest zip entry: the encrypted body as stored, keyed by its entry name. */
export type ArchiveBody = { name: string; blob: Blob }

export type TamperOpts = {
    /** mutate the parsed manifest before it is re-written */
    manifest?: (m: ResultsManifest) => void
    /** mutate the file bodies — reorder, rename, swap, or edit bytes — before they are re-written */
    bodies?: (bodies: ArchiveBody[]) => ArchiveBody[] | void
    /** zip entry names to omit from the rebuilt archive */
    drop?: string[]
    /** extra zip entries to inject, name -> body */
    add?: Record<string, string>
}

/** Split an archive into its manifest and its raw encrypted bodies. */
export async function openArchive(zip: Blob): Promise<{ manifest: ResultsManifest; bodies: ArchiveBody[] }> {
    const entries = await new ZipReader(new BlobReader(zip)).getEntries()

    let manifest: ResultsManifest = { files: {} }
    const bodies: ArchiveBody[] = []
    for (const entry of entries) {
        if (entry.directory) continue
        if (entry.filename === MANIFEST_FILENAME) {
            manifest = JSON.parse(await entry.getData(new TextWriter())) as ResultsManifest
        } else {
            bodies.push({ name: entry.filename, blob: await entry.getData(new BlobWriter()) })
        }
    }
    return { manifest, bodies }
}

/** Pack a manifest and a set of bodies back into an archive. */
export async function packArchive(manifest: ResultsManifest, bodies: ArchiveBody[]): Promise<Blob> {
    const out = new BlobWriter('application/zip')
    const writer = new ZipWriter(out)
    for (const body of bodies) {
        await writer.add(body.name, new BlobReader(body.blob))
    }
    await writer.add(MANIFEST_FILENAME, new TextReader(JSON.stringify(manifest)))
    await writer.close()
    return out.getData()
}

/**
 * Rebuild an archive with the manifest and/or zip entries deliberately out of step. Needed because
 * a fixed ResultsWriter can no longer *produce* drift, yet archives already in storage have it —
 * and a hostile store can forge it at will.
 */
export async function tamper(zip: Blob, opts: TamperOpts): Promise<Blob> {
    const { manifest, bodies } = await openArchive(zip)

    opts.manifest?.(manifest)
    const rewritten = opts.bodies?.(bodies) ?? bodies

    const kept = rewritten.filter((body) => !opts.drop?.includes(body.name))
    const injected = Object.entries(opts.add ?? {}).map(([name, content]) => ({
        name,
        blob: new Blob([content]),
    }))

    return packArchive(manifest, [...kept, ...injected])
}

/**
 * Build an archive exactly as the pre-cipher-field writer did: AES-CBC bodies, a 128-bit IV, and a
 * manifest with neither `version` nor `cipher`.
 *
 * This is the shape of every result already sitting in production storage, so the dual-mode reader
 * has to keep reading it. Reproduced in code rather than checked in as a binary blob so the format
 * it asserts against is legible.
 */
export async function writeLegacyCbcArchive(
    recipients: { fingerprint: string; publicKey: ArrayBuffer }[],
    files: Record<string, ArrayBuffer>,
): Promise<Blob> {
    const { wrapAesKey } = await import('../job-results/crypto')

    const manifest: ResultsManifest = { files: {} }
    const bodies: ArchiveBody[] = []

    for (const [name, content] of Object.entries(files)) {
        const aesKey = await crypto.subtle.generateKey({ name: 'AES-CBC', length: 256 }, true, ['encrypt'])
        const iv = crypto.getRandomValues(new Uint8Array(16))
        const encrypted = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, aesKey, content)
        const rawAesKey = await crypto.subtle.exportKey('raw', aesKey)

        const keys: ResultsManifest['files'][string]['keys'] = {}
        for (const recipient of recipients) {
            keys[recipient.fingerprint] = { crypt: await wrapAesKey(rawAesKey, recipient.publicKey) }
        }

        bodies.push({ name, blob: new Blob([encrypted]) })
        manifest.files[name] = {
            path: name,
            bytes: content.byteLength,
            iv: Buffer.from(iv).toString('base64'),
            keys,
        }
    }

    return packArchive(manifest, bodies)
}

/** Flip one bit in a blob, leaving its length untouched. */
export async function flipByte(blob: Blob, index = 0): Promise<Blob> {
    const bytes = new Uint8Array(await blob.arrayBuffer())
    bytes[index] ^= 0xff
    return new Blob([bytes])
}
