import { describe, it, expect } from 'vitest'
import {
    arrayBufferToHex,
    generateKeyPair,
    fingerprintFromPublicKey,
    fingerprintFromPrivateKey,
    privateKeyFromString,
    serializedBufferToPublicKey,
    pemToArrayBuffer,
    SerializedBuffer,
} from './keypair'
import { readPublicKey } from '../testing'

describe('Encryption Library Tests', () => {
    it('should generate a public/private key pair and export keys', async () => {
        const {
            publicKey,
            privateKey,
            exportedPublicKey,
            exportedPrivateKey,
            publicKeyString,
            privateKeyString,
            fingerprint,
        } = await generateKeyPair()

        expect(publicKey).toBeInstanceOf(CryptoKey)
        expect(privateKey).toBeInstanceOf(CryptoKey)
        expect(exportedPublicKey).toBeInstanceOf(ArrayBuffer)
        expect(exportedPrivateKey).toBeInstanceOf(ArrayBuffer)
        expect(publicKeyString).toBeTypeOf('string')
        expect(privateKeyString).toBeTypeOf('string')
        expect(fingerprint).toBeTypeOf('string')
        expect(fingerprint.length).toBe(64) // SHA-256 hash is 64 hex characters
    })

    it('should create a fingerprint from the public key string', async () => {
        const { publicKeyString } = await generateKeyPair()
        const fingerprint = await fingerprintFromPublicKey(publicKeyString)

        expect(fingerprint).toBeTypeOf('string')
        expect(fingerprint.length).toBe(64) // SHA-256 hash is 64 hex characters
    })

    it('should create a fingerprint from the private key string', async () => {
        const { privateKeyString } = await generateKeyPair()
        const fingerprint = await fingerprintFromPrivateKey(privateKeyString)

        expect(fingerprint).toBeTypeOf('string')
        expect(fingerprint.length).toBe(64) // SHA-256 hash is 64 hex characters
    })

    it('should generate different fingerprints for different key pairs', async () => {
        const { publicKeyString: publicKeyString1 } = await generateKeyPair()
        const { publicKeyString: publicKeyString2 } = await generateKeyPair()

        const fingerprint1 = await fingerprintFromPublicKey(publicKeyString1)
        const fingerprint2 = await fingerprintFromPublicKey(publicKeyString2)

        expect(fingerprint1).not.toEqual(fingerprint2)
    })

    it('should import a private key from a string and create a fingerprint', async () => {
        const { privateKeyString } = await generateKeyPair()
        const privateKey = await privateKeyFromString(privateKeyString)
        const fingerprint = await fingerprintFromPrivateKey(privateKey)
        expect(fingerprint).toBeTypeOf('string')
        expect(fingerprint.length).toBe(64) // SHA-256 hash is 64 hex characters
    })

    it('can parse a public key from binary data', async () => {
        const pubKeyStr = readPublicKey()
        const origFingerprint = await fingerprintFromPublicKey(pubKeyStr)
        // this is what is produced by JSON.stringify a node Buffer
        const serialized = JSON.parse(JSON.stringify(Buffer.from(pemToArrayBuffer(pubKeyStr)))) as SerializedBuffer
        const publicKey = await serializedBufferToPublicKey(serialized)
        const exportedKey = await crypto.subtle.exportKey('spki', publicKey)
        const afterConversionFingerprint = await crypto.subtle.digest('SHA-256', exportedKey)

        expect(origFingerprint).toEqual(arrayBufferToHex(afterConversionFingerprint))
    })
})
