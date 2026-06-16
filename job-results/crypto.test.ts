import { describe, it, expect } from 'vitest'
import { readPublicKey, readPrivateKey } from '../testing'
import { fingerprintKeyData, pemToArrayBuffer, generateKeyPair } from '../util'
import { ResultsWriter } from './writer'
import { ResultsReader } from './reader'
import { unwrapAesKey, wrapAesKey } from './crypto'

const toArrayBuffer = (str: string): ArrayBuffer => {
    const buf = Buffer.from(str, 'utf-8')
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)
}

describe('wrapAesKey / unwrapAesKey', () => {
    it('round-trips a raw AES key through an RSA keypair', async () => {
        const publicKey = pemToArrayBuffer(readPublicKey())
        const privateKey = pemToArrayBuffer(readPrivateKey())

        const aesKey = await crypto.subtle.generateKey({ name: 'AES-CBC', length: 256 }, true, ['encrypt'])
        const rawAesKey = await crypto.subtle.exportKey('raw', aesKey)

        const crypt = await wrapAesKey(rawAesKey, publicKey)
        const { rawAesKey: unwrapped } = await unwrapAesKey(crypt, privateKey)

        expect(new Uint8Array(unwrapped)).toEqual(new Uint8Array(rawAesKey))
    })
})

describe('ResultsReader override keys (researcher re-wrap)', () => {
    it('lets a researcher decrypt with a re-wrapped key absent from the manifest', async () => {
        // Data owner encrypts results for their own key only.
        const doPublic = pemToArrayBuffer(readPublicKey())
        const doFingerprint = await fingerprintKeyData(doPublic)
        const doPrivate = pemToArrayBuffer(readPrivateKey())

        const writer = new ResultsWriter([{ publicKey: doPublic, fingerprint: doFingerprint }])
        await writer.addFile('result.csv', toArrayBuffer('secret,data'))
        const zip = await writer.generate()

        // Reviewer reads with their manifest key and recovers each file's raw AES key.
        const reviewer = new ResultsReader(zip, doPrivate, doFingerprint)
        const [entry] = await reviewer.extractFilesWithKeys()
        expect(new TextDecoder().decode(entry.contents)).toBe('secret,data')
        expect(entry.rawAesKey.byteLength).toBe(32)

        // Researcher: brand-new keypair, NOT an original manifest recipient.
        const researcher = await generateKeyPair()
        const researcherFp = await fingerprintKeyData(researcher.exportedPublicKey)
        const crypt = await wrapAesKey(entry.rawAesKey, researcher.exportedPublicKey)

        // Same ciphertext + IV; only the wrapped key differs, supplied as an override.
        const reader = new ResultsReader(zip, researcher.exportedPrivateKey, researcherFp, {
            'result.csv': crypt,
        })
        const [out] = await reader.extractFiles()
        expect(new TextDecoder().decode(out.contents)).toBe('secret,data')
    })

    it('still reads with the manifest fingerprint when no override is supplied', async () => {
        const publicKey = pemToArrayBuffer(readPublicKey())
        const fingerprint = await fingerprintKeyData(publicKey)
        const privateKey = pemToArrayBuffer(readPrivateKey())

        const writer = new ResultsWriter([{ publicKey, fingerprint }])
        await writer.addFile('a.txt', toArrayBuffer('alpha'))
        const zip = await writer.generate()

        const reader = new ResultsReader(zip, privateKey, fingerprint)
        const [out] = await reader.extractFiles()
        expect(new TextDecoder().decode(out.contents)).toBe('alpha')
    })
})
