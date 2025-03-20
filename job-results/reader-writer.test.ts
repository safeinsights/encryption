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

        await writer.addFile('test.data', Buffer.from('hello world!', 'utf-8'))

        expect(writer.manifest.files['test.data']).toMatchObject({
            path: 'test.data',
            bytes: 12,
        })

        const zip = await writer.generate()

        const reader = new ResultsReader(zip)

        const privateKey = pemToArrayBuffer(readPrivateKey())

        const entries = await reader.decryptZip(privateKey, fingerprint)

        expect(Object.keys(reader.manifest.files)).toHaveLength(1)
        expect(entries).toHaveLength(1)
        expect(entries[0]).toEqual('hello world!')
    })
})
