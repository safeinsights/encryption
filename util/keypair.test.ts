import { describe, it, expect } from 'vitest'
import {
    arrayBufferToHex,
    generateKeyPair,
    fingerprintKeyData,
    serializedBufferToPublicKey,
    pemToArrayBuffer,
    SerializedBuffer,
} from './keypair'
import { readPublicKey } from '../testing'

describe('Encryption Library KeyPair Tests', () => {
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
        const { exportedPublicKey } = await generateKeyPair()
        const fingerprint = await fingerprintKeyData(exportedPublicKey)

        expect(fingerprint).toBeTypeOf('string')
        expect(fingerprint.length).toBe(64) // SHA-256 hash is 64 hex characters
    })

    it('should create a fingerprint from the private key string', async () => {
        const { exportedPrivateKey } = await generateKeyPair()
        const fingerprint = await fingerprintKeyData(exportedPrivateKey)

        expect(fingerprint).toBeTypeOf('string')
        expect(fingerprint.length).toBe(64) // SHA-256 hash is 64 hex characters
    })

    it('should generate different fingerprints for different key pairs', async () => {
        const { exportedPrivateKey: publicKeyData1 } = await generateKeyPair()
        const { exportedPrivateKey: publicKeyData2 } = await generateKeyPair()

        const fingerprint1 = await fingerprintKeyData(publicKeyData1)
        const fingerprint2 = await fingerprintKeyData(publicKeyData2)

        expect(fingerprint1).not.toEqual(fingerprint2)
    })

    it('can parse a public key from binary data', async () => {
        const pubKeyStr = readPublicKey()
        const origFingerprint = await fingerprintKeyData(pemToArrayBuffer(pubKeyStr))

        // this is what is produced by JSON.stringify a node Buffer
        const serialized = JSON.parse(JSON.stringify(Buffer.from(pemToArrayBuffer(pubKeyStr)))) as SerializedBuffer
        const publicKey = await serializedBufferToPublicKey(serialized)
        const exportedKey = await crypto.subtle.exportKey('spki', publicKey)
        const afterConversionFingerprint = await crypto.subtle.digest('SHA-256', exportedKey)

        expect(origFingerprint).toEqual(arrayBufferToHex(afterConversionFingerprint))
    })
})
