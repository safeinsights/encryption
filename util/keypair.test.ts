import { describe, it, expect } from 'vitest'
import { generateKeyPair, exportKey, createFingerprint } from './keypair' // Adjust the import according to your file structure

describe('Encryption Library Tests', () => {
    it('should generate a public/private key pair', async () => {
        const { publicKey, privateKey } = await generateKeyPair()

        expect(publicKey).toBeInstanceOf(CryptoKey)
        expect(privateKey).toBeInstanceOf(CryptoKey)
    })

    it('should export a public key in SPKI format', async () => {
        const { publicKey } = await generateKeyPair()
        const exportedKey = await exportKey(publicKey, 'spki')

        expect(exportedKey).toBeInstanceOf(ArrayBuffer)
        expect(exportedKey.byteLength).toBeGreaterThan(0)
    })

    it('should export a private key in PKCS8 format', async () => {
        const { privateKey } = await generateKeyPair()
        const exportedKey = await exportKey(privateKey, 'pkcs8')

        expect(exportedKey).toBeInstanceOf(ArrayBuffer)
        expect(exportedKey.byteLength).toBeGreaterThan(0)
    })

    it('should create a fingerprint from the public key', async () => {
        const { publicKey } = await generateKeyPair()
        const fingerprint = await createFingerprint(publicKey)

        expect(fingerprint).toBeTypeOf('string')
        expect(fingerprint.length).toBe(64) // SHA-256 hash is 64 hex characters
    })

    it('should generate different fingerprints for different key pairs', async () => {
        const { publicKey: publicKey1 } = await generateKeyPair()
        const { publicKey: publicKey2 } = await generateKeyPair()

        const fingerprint1 = await createFingerprint(publicKey1)
        const fingerprint2 = await createFingerprint(publicKey2)

        expect(fingerprint1).not.toEqual(fingerprint2)
    })
})
