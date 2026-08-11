import { describe, it, expect } from 'vitest'
import { readPublicKey, readPrivateKey } from '../testing'
import { tamper } from '../testing/archive'
import { fingerprintKeyData, pemToArrayBuffer } from '../util'
import { ResultsWriter } from './writer'
import { ResultsReader } from './reader'

const toArrayBuffer = (str: string): ArrayBuffer => {
    const buf = Buffer.from(str, 'utf-8')
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)
}

describe('manifest/zip reconciliation', async () => {
    const publicKey = pemToArrayBuffer(readPublicKey())
    const fingerprint = await fingerprintKeyData(publicKey)
    const privateKey = pemToArrayBuffer(readPrivateKey())

    const files = [
        { name: 'alpha.txt', content: 'Alpha content here' },
        { name: 'beta.csv', content: 'col1,col2\nval1,val2' },
    ]

    async function buildZip() {
        const writer = new ResultsWriter([{ publicKey, fingerprint }])
        for (const f of files) await writer.addFile(f.name, toArrayBuffer(f.content))
        return writer.generate()
    }

    const readerFor = (zip: Blob) => new ResultsReader(zip, privateKey, fingerprint)

    it('reports a clean archive as fully matched, ignoring manifest.json itself', async () => {
        const report = await readerFor(await buildZip()).reconcile()

        expect(report.matched.sort()).toEqual(['alpha.txt', 'beta.csv'])
        expect(report.missingFromZip).toEqual([])
        expect(report.extraInZip).toEqual([])
        expect(report.normalized).toEqual([])
    })

    it('throws rather than silently dropping a manifest file missing from the zip', async () => {
        const zip = await tamper(await buildZip(), { drop: ['beta.csv'] })

        await expect(readerFor(zip).extractFiles()).rejects.toThrow(/beta\.csv/)
    })

    it('throws on a zip entry the manifest does not list', async () => {
        const zip = await tamper(await buildZip(), { add: { 'sneaky.bin': 'injected' } })

        await expect(readerFor(zip).extractFiles()).rejects.toThrow(/sneaky\.bin/)
    })

    it('recovers a whitespace-drifted manifest key instead of losing the file', async () => {
        // reproduces production drift: zip.js trimmed the entry name on add, the old writer stored
        // the untrimmed name as the manifest key
        const zip = await tamper(await buildZip(), {
            manifest: (m) => {
                m.files[' alpha.txt '] = { ...m.files['alpha.txt'], path: ' alpha.txt ' }
                delete m.files['alpha.txt']
            },
        })

        const reader = readerFor(zip)
        const entries = await reader.extractFiles()

        expect(entries.map((e) => e.path).sort()).toEqual(['alpha.txt', 'beta.csv'])
        expect((await reader.reconcile()).normalized).toEqual([{ manifestKey: ' alpha.txt ', zipName: 'alpha.txt' }])
    })

    it('throws when two manifest keys normalize onto the same zip entry', async () => {
        const zip = await tamper(await buildZip(), {
            manifest: (m) => {
                m.files[' alpha.txt'] = { ...m.files['alpha.txt'], path: ' alpha.txt' }
            },
        })

        await expect(readerFor(zip).extractFiles()).rejects.toThrow(/ambiguous/i)
    })

    it('partial:true returns the readable files and still reports the drift', async () => {
        const zip = await tamper(await buildZip(), { drop: ['beta.csv'] })
        const reader = readerFor(zip)

        const entries = await reader.extractFiles({ partial: true })

        expect(entries.map((e) => e.path)).toEqual(['alpha.txt'])
        expect((await reader.reconcile()).missingFromZip).toEqual(['beta.csv'])
    })

    it('listFiles agrees with extractFiles on a whitespace-drifted archive', async () => {
        // the reported defect: the drifted name was dropped from extractFiles yet still listed by
        // listFiles, so a reviewer saw a file they could never receive
        const zip = await tamper(await buildZip(), {
            manifest: (m) => {
                m.files[' alpha.txt '] = { ...m.files['alpha.txt'], path: ' alpha.txt ' }
                delete m.files['alpha.txt']
            },
        })
        const reader = readerFor(zip)

        const listed = (await reader.listFiles()).map((f) => f.path).sort()
        const extracted = (await reader.extractFiles()).map((e) => e.path).sort()

        expect(listed).toEqual(extracted)
        expect(listed).toEqual(['alpha.txt', 'beta.csv'])
    })

    it('listFiles refuses to advertise a file the zip cannot supply', async () => {
        const zip = await tamper(await buildZip(), { drop: ['beta.csv'] })

        await expect(readerFor(zip).listFiles()).rejects.toThrow(/beta\.csv/)
    })

    it('listFiles with partial:true lists only what is actually readable', async () => {
        const zip = await tamper(await buildZip(), { drop: ['beta.csv'] })

        const listed = await readerFor(zip).listFiles({ partial: true })

        expect(listed.map((f) => f.path)).toEqual(['alpha.txt'])
        expect(listed[0].bytes).toBe(Buffer.byteLength('Alpha content here', 'utf-8'))
    })

    it('extractFile resolves a whitespace-drifted manifest key', async () => {
        const zip = await tamper(await buildZip(), {
            manifest: (m) => {
                m.files[' alpha.txt '] = { ...m.files['alpha.txt'], path: ' alpha.txt ' }
                delete m.files['alpha.txt']
            },
        })

        const entry = await readerFor(zip).extractFile(' alpha.txt ')
        expect(new TextDecoder().decode(entry.contents)).toBe('Alpha content here')
    })
})

describe('writer filename normalization', async () => {
    const publicKey = pemToArrayBuffer(readPublicKey())
    const fingerprint = await fingerprintKeyData(publicKey)

    it('stores the same trimmed name in the zip and the manifest', async () => {
        const writer = new ResultsWriter([{ publicKey, fingerprint }])
        await writer.addFile(' spaced.txt ', toArrayBuffer('payload'))

        expect(Object.keys(writer.manifest.files)).toEqual(['spaced.txt'])
        expect(writer.manifest.files['spaced.txt'].path).toBe('spaced.txt')

        const report = await new ResultsReader(
            await writer.generate(),
            pemToArrayBuffer(readPrivateKey()),
            fingerprint,
        ).reconcile()
        expect(report.matched).toEqual(['spaced.txt'])
        expect(report.normalized).toEqual([])
    })

    it('throws on a name that is empty once trimmed', async () => {
        const writer = new ResultsWriter([{ publicKey, fingerprint }])

        await expect(writer.addFile('   ', toArrayBuffer('x'))).rejects.toThrow(/filename/i)
    })

    it('throws on a name colliding with one already added', async () => {
        const writer = new ResultsWriter([{ publicKey, fingerprint }])
        await writer.addFile('dup.txt', toArrayBuffer('first'))

        await expect(writer.addFile(' dup.txt', toArrayBuffer('second'))).rejects.toThrow(/duplicate/i)
        expect(Object.keys(writer.manifest.files)).toEqual(['dup.txt'])
    })
})
