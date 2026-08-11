import { describe, it, expect } from 'vitest'
import { readPublicKey, readPrivateKey } from '../testing'
import { flipByte, openArchive, packArchive, tamper, writeLegacyCbcArchive } from '../testing/archive'
import { fingerprintKeyData, pemToArrayBuffer } from '../util'
import { ResultsWriter } from './writer'
import { ResultsReader, ResultsIntegrityError } from './reader'
import { decryptFile, CURRENT_CIPHER, LEGACY_CIPHER, MANIFEST_VERSION, GCM_IV_BYTES } from './crypto'

const toArrayBuffer = (str: string): ArrayBuffer => {
    const buf = Buffer.from(str, 'utf-8')
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)
}

const publicKey = pemToArrayBuffer(readPublicKey())
const privateKey = pemToArrayBuffer(readPrivateKey())
const fingerprint = await fingerprintKeyData(publicKey)
const recipient = { publicKey, fingerprint }

const JOB_ID = 'job-4711'

async function buildArchive(
    files: Record<string, string>,
    options: { jobId?: string } = { jobId: JOB_ID },
): Promise<Blob> {
    const writer = new ResultsWriter([recipient], options)
    for (const [name, content] of Object.entries(files)) {
        await writer.addFile(name, toArrayBuffer(content))
    }
    return writer.generate()
}

const readerFor = (zip: Blob, options = {}) => new ResultsReader(zip, privateKey, fingerprint, {}, options)

describe('manifest is self-describing', () => {
    it('stamps version, cipher and job id, and round-trips', async () => {
        const writer = new ResultsWriter([recipient], { jobId: JOB_ID })
        await writer.addFile('result.csv', toArrayBuffer('col1,col2'))

        expect(writer.manifest).toMatchObject({
            version: MANIFEST_VERSION,
            cipher: CURRENT_CIPHER,
            jobId: JOB_ID,
        })

        const [entry] = await readerFor(await writer.generate(), { jobId: JOB_ID }).extractFiles()
        expect(new TextDecoder().decode(entry.contents)).toBe('col1,col2')
    })

    it('uses a 96-bit IV, the size AES-GCM is specified for', async () => {
        const zip = await buildArchive({ 'a.txt': 'alpha' })
        const { manifest } = await openArchive(zip)

        expect(Buffer.from(manifest.files['a.txt'].iv, 'base64')).toHaveLength(GCM_IV_BYTES)
    })

    it('omits jobId when the writer was not given one, and still reads', async () => {
        const zip = await buildArchive({ 'a.txt': 'alpha' }, {})
        const { manifest } = await openArchive(zip)

        expect(manifest.jobId).toBeUndefined()

        const [entry] = await readerFor(zip).extractFiles()
        expect(new TextDecoder().decode(entry.contents)).toBe('alpha')
    })

    it('rejects an empty job id rather than binding to nothing', () => {
        expect(() => new ResultsWriter([recipient], { jobId: '  ' })).toThrow(/non-empty/i)
    })
})

describe('tamper detection', () => {
    it('rejects a flipped ciphertext byte instead of returning garbage', async () => {
        const { manifest, bodies } = await openArchive(await buildArchive({ 'a.txt': 'alpha' }))
        const corrupted = await packArchive(manifest, [{ name: bodies[0].name, blob: await flipByte(bodies[0].blob) }])

        await expect(readerFor(corrupted).extractFiles()).rejects.toThrow()
    })

    it('rejects a modified IV', async () => {
        const zip = await tamper(await buildArchive({ 'a.txt': 'alpha' }), {
            manifest: (m) => {
                const iv = Buffer.from(m.files['a.txt'].iv, 'base64')
                iv[0] ^= 0xff
                m.files['a.txt'].iv = iv.toString('base64')
            },
        })

        await expect(readerFor(zip).extractFiles()).rejects.toThrow()
    })

    it('rejects a body swapped between two paths in the same archive', async () => {
        // classic cross-file swap: the whole triple — ciphertext, IV and wrapped key — moves
        // together, so nothing is internally inconsistent. Only the path bound in the AAD differs.
        const zip = await buildArchive({ 'public.csv': 'safe to release', 'private.csv': 'PHI, do not release' })
        const { manifest, bodies } = await openArchive(zip)

        const swapped = await packArchive(
            {
                ...manifest,
                files: {
                    'public.csv': { ...manifest.files['private.csv'], path: 'public.csv' },
                    'private.csv': { ...manifest.files['public.csv'], path: 'private.csv' },
                },
            },
            bodies.map((body) => ({
                name: body.name === 'public.csv' ? 'private.csv' : 'public.csv',
                blob: body.blob,
            })),
        )

        await expect(readerFor(swapped).extractFiles()).rejects.toThrow()
    })

    it('rejects a file spliced in from another job for the same recipient', async () => {
        const target = await buildArchive({ 'result.csv': 'the real result' }, { jobId: 'job-target' })
        const donor = await buildArchive({ 'result.csv': 'a result from elsewhere' }, { jobId: 'job-donor' })

        const targetParts = await openArchive(target)
        const donorParts = await openArchive(donor)

        // Same recipient, same path, same archive layout — only the job the body was bound to differs.
        const spliced = await packArchive(
            { ...targetParts.manifest, files: { 'result.csv': donorParts.manifest.files['result.csv'] } },
            donorParts.bodies,
        )

        await expect(readerFor(spliced).extractFiles()).rejects.toThrow()
    })

    it('rejects a renamed entry even when manifest and zip are renamed together', async () => {
        const zip = await buildArchive({ 'a.txt': 'alpha' })
        const { manifest, bodies } = await openArchive(zip)

        const renamed = await packArchive(
            { ...manifest, files: { 'b.txt': { ...manifest.files['a.txt'], path: 'b.txt' } } },
            [{ name: 'b.txt', blob: bodies[0].blob }],
        )

        await expect(readerFor(renamed).extractFiles()).rejects.toThrow()
    })

    it('rejects a body forged with a freshly wrapped key under a different job', async () => {
        // The attack the AAD exists for: RSA-OAEP wrapping is public, so a hostile store holding
        // the recipient's public key can mint its own AES key and encrypt whatever it likes. Bound
        // to the wrong job, that forgery no longer decrypts.
        const forged = await buildArchive({ 'result.csv': 'fabricated findings' }, { jobId: 'not-the-real-job' })
        const { manifest, bodies } = await openArchive(forged)

        const relabelled = await packArchive({ ...manifest, jobId: JOB_ID }, bodies)

        await expect(readerFor(relabelled, { jobId: JOB_ID }).extractFiles()).rejects.toThrow()
    })
})

describe('job id verification', () => {
    it('reads when the expected job id matches the manifest', async () => {
        const zip = await buildArchive({ 'a.txt': 'alpha' })

        const [entry] = await readerFor(zip, { jobId: JOB_ID }).extractFiles()
        expect(new TextDecoder().decode(entry.contents)).toBe('alpha')
    })

    it('refuses a whole archive swapped in from another job', async () => {
        const zip = await buildArchive({ 'a.txt': 'alpha' }, { jobId: 'some-other-job' })

        await expect(readerFor(zip, { jobId: JOB_ID }).extractFiles()).rejects.toThrow(ResultsIntegrityError)
        await expect(readerFor(zip, { jobId: JOB_ID }).extractFiles()).rejects.toThrow(/some-other-job/)
    })

    it('refuses an unbound GCM archive when a job id was expected', async () => {
        const zip = await buildArchive({ 'a.txt': 'alpha' }, {})

        await expect(readerFor(zip, { jobId: JOB_ID }).extractFiles()).rejects.toThrow(/declares no job id/i)
    })

    it('does not check the job id when the caller supplies none', async () => {
        const zip = await buildArchive({ 'a.txt': 'alpha' }, { jobId: 'some-other-job' })

        const [entry] = await readerFor(zip).extractFiles()
        expect(new TextDecoder().decode(entry.contents)).toBe('alpha')
    })
})

describe('legacy AES-CBC archives (dual-mode read)', () => {
    const legacyFiles = { 'legacy.csv': 'written before the cipher field existed' }

    async function buildLegacy() {
        return writeLegacyCbcArchive([recipient], { 'legacy.csv': toArrayBuffer(legacyFiles['legacy.csv']) })
    }

    it('reads an archive whose manifest declares no cipher or version', async () => {
        const zip = await buildLegacy()
        const { manifest } = await openArchive(zip)
        expect(manifest.cipher).toBeUndefined()
        expect(manifest.version).toBeUndefined()

        const [entry] = await readerFor(zip).extractFiles()
        expect(new TextDecoder().decode(entry.contents)).toBe(legacyFiles['legacy.csv'])
    })

    it('reads an archive that declares AES-CBC explicitly', async () => {
        const zip = await tamper(await buildLegacy(), {
            manifest: (m) => {
                m.cipher = LEGACY_CIPHER
            },
        })

        const [entry] = await readerFor(zip).extractFiles()
        expect(new TextDecoder().decode(entry.contents)).toBe(legacyFiles['legacy.csv'])
    })

    it('refuses a legacy archive once authenticated ciphers are required', async () => {
        const zip = await buildLegacy()

        await expect(readerFor(zip, { requireAuthenticatedCipher: true }).extractFiles()).rejects.toThrow(
            /unauthenticated cipher/i,
        )
    })

    it('accepts a current archive under the same requirement', async () => {
        const zip = await buildArchive({ 'a.txt': 'alpha' })

        const [entry] = await readerFor(zip, { requireAuthenticatedCipher: true }).extractFiles()
        expect(new TextDecoder().decode(entry.contents)).toBe('alpha')
    })
})

describe('manifest validation fails closed', () => {
    it('refuses an unknown cipher rather than guessing', async () => {
        const zip = await tamper(await buildArchive({ 'a.txt': 'alpha' }), {
            manifest: (m) => {
                m.cipher = 'AES-CTR' as never
            },
        })

        await expect(readerFor(zip).extractFiles()).rejects.toThrow(/unsupported manifest cipher/i)
    })

    it('refuses a manifest version newer than this build understands', async () => {
        const zip = await tamper(await buildArchive({ 'a.txt': 'alpha' }), {
            manifest: (m) => {
                m.version = MANIFEST_VERSION + 1
            },
        })

        await expect(readerFor(zip).extractFiles()).rejects.toThrow(/unsupported manifest version/i)
    })

    it('refuses a non-integer version', async () => {
        const zip = await tamper(await buildArchive({ 'a.txt': 'alpha' }), {
            manifest: (m) => {
                m.version = 'two' as never
            },
        })

        await expect(readerFor(zip).extractFiles()).rejects.toThrow(/unsupported manifest version/i)
    })

    it('refuses a downgrade that strips the cipher field off GCM bodies', async () => {
        // The cheapest downgrade attempt: drop `cipher` so the reader treats authenticated bodies
        // as legacy CBC. It must not silently succeed — CBC over GCM ciphertext is not plaintext.
        //
        // 'alpha' is 5 bytes, so the GCM body is 5 + 16 = 21 bytes and CBC rejects it outright on
        // block alignment. Keep the payload length off a 16-byte multiple: at an exact multiple,
        // rejection would fall to the PKCS#7 padding check, which passes by chance ~1 time in 256.
        const zip = await tamper(await buildArchive({ 'a.txt': 'alpha' }), {
            manifest: (m) => {
                delete m.cipher
                delete m.version
            },
        })

        await expect(readerFor(zip).extractFiles()).rejects.toThrow()
    })
})

describe('decryptFile standalone helper', () => {
    it('decrypts a GCM body when given its path and job id', async () => {
        const zip = await buildArchive({ 'a.txt': 'alpha' })
        const { manifest, bodies } = await openArchive(zip)
        const file = manifest.files['a.txt']

        const { contents } = await decryptFile({
            body: await bodies[0].blob.arrayBuffer(),
            iv: file.iv,
            crypt: file.keys[fingerprint].crypt,
            privateKey,
            cipher: CURRENT_CIPHER,
            path: 'a.txt',
            jobId: JOB_ID,
        })

        expect(new TextDecoder().decode(contents)).toBe('alpha')
    })

    it('rejects a GCM body when the job id does not match', async () => {
        const zip = await buildArchive({ 'a.txt': 'alpha' })
        const { manifest, bodies } = await openArchive(zip)
        const file = manifest.files['a.txt']

        await expect(
            decryptFile({
                body: await bodies[0].blob.arrayBuffer(),
                iv: file.iv,
                crypt: file.keys[fingerprint].crypt,
                privateKey,
                cipher: CURRENT_CIPHER,
                path: 'a.txt',
                jobId: 'wrong-job',
            }),
        ).rejects.toThrow()
    })
})
