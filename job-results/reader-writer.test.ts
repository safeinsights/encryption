import { describe, it, expect } from 'vitest'
import { readPublicKey, readPrivateKey } from '../testing'
import { fingerprintKeyData, pemToArrayBuffer } from '../util'
import { ResultsWriter } from './writer'
import { ResultsReader } from './reader'

const toArrayBuffer = (str: string): ArrayBuffer => {
    const buf = Buffer.from(str, 'utf-8')
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)
}

describe('Encryption Library Tests', async () => {
    it('can create a results file and read it', async () => {
        const publicKey = pemToArrayBuffer(readPublicKey())
        const fingerprint = await fingerprintKeyData(publicKey)
        const writer = new ResultsWriter([
            {
                publicKey,
                fingerprint,
            },
        ])

        const content = Buffer.from('hello world!', 'utf-8')
        await writer.addFile(
            'test.data',
            content.buffer.slice(content.byteOffset, content.byteOffset + content.byteLength),
        )

        expect(writer.manifest.files['test.data']).toMatchObject({
            path: 'test.data',
            bytes: 12,
        })

        const zip = await writer.generate()

        const privateKey = pemToArrayBuffer(readPrivateKey())
        const reader = new ResultsReader(zip, privateKey, fingerprint)

        const entries = await reader.extractFiles()

        expect(Object.keys(reader.manifest.files)).toHaveLength(1)
        expect(entries).toHaveLength(1)
        expect(entries[0].path).toEqual('test.data')

        expect(new TextDecoder().decode(entries[0].contents)).toEqual('hello world!')
    })
})

describe('listFiles and extractFile', async () => {
    const publicKey = pemToArrayBuffer(readPublicKey())
    const fingerprint = await fingerprintKeyData(publicKey)
    const privateKey = pemToArrayBuffer(readPrivateKey())

    const testFiles = [
        { name: 'alpha.txt', content: 'Alpha content here' },
        { name: 'beta.csv', content: 'col1,col2\nval1,val2' },
        { name: 'gamma.json', content: '{"key":"value"}' },
    ]

    async function buildZip() {
        const writer = new ResultsWriter([{ publicKey, fingerprint }])
        for (const f of testFiles) {
            await writer.addFile(f.name, toArrayBuffer(f.content))
        }
        return writer.generate()
    }

    it('listFiles returns correct names and sizes', async () => {
        const zip = await buildZip()
        const reader = new ResultsReader(zip, privateKey, fingerprint)

        const files = await reader.listFiles()

        expect(files).toHaveLength(3)
        for (const f of testFiles) {
            const info = files.find((fi) => fi.path === f.name)
            expect(info).toBeDefined()
            expect(info!.bytes).toBe(Buffer.byteLength(f.content, 'utf-8'))
        }
    })

    it('extractFile decrypts a single file correctly', async () => {
        const zip = await buildZip()
        const reader = new ResultsReader(zip, privateKey, fingerprint)

        const entry = await reader.extractFile('beta.csv')

        expect(entry.path).toBe('beta.csv')
        expect(new TextDecoder().decode(entry.contents)).toBe('col1,col2\nval1,val2')
    })

    it('extractFile throws for non-existent file', async () => {
        const zip = await buildZip()
        const reader = new ResultsReader(zip, privateKey, fingerprint)

        await expect(reader.extractFile('nope.txt')).rejects.toThrow('File not found in manifest: nope.txt')
    })

    it('listFiles then extractFile works together', async () => {
        const zip = await buildZip()
        const reader = new ResultsReader(zip, privateKey, fingerprint)

        const files = await reader.listFiles()
        expect(files).toHaveLength(3)

        const entry = await reader.extractFile('gamma.json')
        expect(new TextDecoder().decode(entry.contents)).toBe('{"key":"value"}')
    })

    it('extractFile works without prior listFiles call', async () => {
        const zip = await buildZip()
        const reader = new ResultsReader(zip, privateKey, fingerprint)

        const entry = await reader.extractFile('alpha.txt')
        expect(new TextDecoder().decode(entry.contents)).toBe('Alpha content here')
    })
})
