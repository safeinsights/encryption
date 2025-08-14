import { describe, it, expect } from 'vitest'
import { readPublicKey, readPrivateKey } from '../testing'
import { fingerprintKeyData, pemToArrayBuffer } from '../util'
import { ResultsWriter } from './writer'
import { ResultsReader } from './reader'

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
