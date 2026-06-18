import { describe, it, expect } from 'vitest'
import { readPublicKey, readPrivateKey } from '../testing'
import { fingerprintKeyData, pemToArrayBuffer, generateKeyPair } from '../util'
import { ResultsWriter } from './writer'
import { ResultsReader } from './reader'
import { unwrapAesKey, wrapAesKey, decryptFile } from './crypto'

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

describe('decryptFile', () => {
    it('decrypts a standalone body + metadata and returns the raw AES key', async () => {
        const publicKey = pemToArrayBuffer(readPublicKey())
        const privateKey = pemToArrayBuffer(readPrivateKey())

        // Encrypt a body with AES-CBC, then RSA-wrap the AES key.
        const aesKey = await crypto.subtle.generateKey({ name: 'AES-CBC', length: 256 }, true, ['encrypt'])
        const rawAesKey = await crypto.subtle.exportKey('raw', aesKey)
        const iv = crypto.getRandomValues(new Uint8Array(16))
        const plaintext = toArrayBuffer('secret,data')
        const body = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, aesKey, plaintext)
        const crypt = await wrapAesKey(rawAesKey, publicKey)

        const { contents, rawAesKey: recovered } = await decryptFile({
            body,
            iv: Buffer.from(iv).toString('base64'),
            crypt,
            privateKey,
        })

        expect(new TextDecoder().decode(contents)).toBe('secret,data')
        expect(new Uint8Array(recovered)).toEqual(new Uint8Array(rawAesKey))
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

    it('throws cleanly when an override is wrapped for a different keypair', async () => {
        const doPublic = pemToArrayBuffer(readPublicKey())
        const doFingerprint = await fingerprintKeyData(doPublic)

        const writer = new ResultsWriter([{ publicKey: doPublic, fingerprint: doFingerprint }])
        await writer.addFile('result.csv', toArrayBuffer('secret,data'))
        const zip = await writer.generate()

        const reviewer = new ResultsReader(zip, pemToArrayBuffer(readPrivateKey()), doFingerprint)
        const [entry] = await reviewer.extractFilesWithKeys()

        // Wrap the raw key for researcher A, but hand the reader researcher B's private key.
        const researcherA = await generateKeyPair()
        const researcherB = await generateKeyPair()
        const crypt = await wrapAesKey(entry.rawAesKey, researcherA.exportedPublicKey)

        const reader = new ResultsReader(zip, researcherB.exportedPrivateKey, researcherB.fingerprint, {
            'result.csv': crypt,
        })
        // RSA-OAEP unwrap fails on the mismatched key — deterministic throw, never garbage plaintext.
        await expect(reader.extractFiles()).rejects.toThrow()
    })

    it('throws when a manifest file has neither a fingerprint match nor an override', async () => {
        const doPublic = pemToArrayBuffer(readPublicKey())
        const doFingerprint = await fingerprintKeyData(doPublic)

        const writer = new ResultsWriter([{ publicKey: doPublic, fingerprint: doFingerprint }])
        await writer.addFile('a.csv', toArrayBuffer('alpha'))
        await writer.addFile('b.csv', toArrayBuffer('beta'))
        const zip = await writer.generate()

        const researcher = await generateKeyPair()
        // Override supplied for a.csv only; b.csv has no key for this researcher.
        const decrypted = await new ResultsReader(
            zip,
            pemToArrayBuffer(readPrivateKey()),
            doFingerprint,
        ).extractFilesWithKeys()
        const aEntry = decrypted.find((e) => e.path === 'a.csv')!
        const crypt = await wrapAesKey(aEntry.rawAesKey, researcher.exportedPublicKey)

        const reader = new ResultsReader(zip, researcher.exportedPrivateKey, researcher.fingerprint, {
            'a.csv': crypt,
        })
        await expect(reader.extractFiles()).rejects.toThrow(/key signature/)
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
