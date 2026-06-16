import { privateKeyFromBuffer } from '../util'
import logger from '../lib/logger'

/**
 * Symmetric algorithm used for file bodies. AES-GCM is authenticated (AEAD):
 * decryption fails loudly if the ciphertext or IV is tampered with, unlike the
 * malleable AES-CBC it replaced.
 */
export const AES_ALGORITHM = 'AES-GCM' as const

/**
 * Decrypt (unwrap) a file's AES key using an RSA private key.
 *
 * Returns both a ready-to-use AES-GCM `CryptoKey` and the raw key bytes.
 * The raw bytes are what re-wrap needs: to grant another recipient access we
 * RSA-encrypt these same bytes for their public key (see {@link wrapAesKey}),
 * leaving the file ciphertext untouched.
 */
export async function unwrapAesKey(
    crypt: string,
    privateKey: ArrayBuffer,
): Promise<{ aesKey: CryptoKey; rawAesKey: ArrayBuffer }> {
    const encryptedKey = Buffer.from(crypt, 'base64')

    const rawAesKey = await crypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        await privateKeyFromBuffer(privateKey),
        encryptedKey,
    )

    const aesKey = await crypto.subtle.importKey('raw', rawAesKey, { name: AES_ALGORITHM }, false, ['decrypt'])

    return { aesKey, rawAesKey }
}

/**
 * Wrap a raw AES key for a recipient's RSA public key — the re-wrap primitive.
 * Produces a new base64 "PO box" (`crypt`) that only that recipient can open;
 * the file body and IV are never re-encrypted.
 */
export async function wrapAesKey(rawAesKey: ArrayBuffer, publicKey: ArrayBuffer): Promise<string> {
    const key = await crypto.subtle.importKey('spki', publicKey, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, [
        'encrypt',
    ])

    const encryptedKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, rawAesKey)

    return Buffer.from(encryptedKey).toString('base64')
}

export async function decryptFileBody(body: ArrayBuffer, iv: BufferSource, aesKey: CryptoKey): Promise<ArrayBuffer> {
    return crypto.subtle.decrypt({ name: AES_ALGORITHM, iv }, aesKey, body)
}

/**
 * Zip-free decrypt of a single file body + its metadata. Mirrors what
 * {@link ResultsReader} does internally, but operates on a standalone encrypted
 * body rather than iterating a zip archive.
 *
 * Also returns the raw AES key so the caller (the reviewer's browser) can re-wrap
 * it for researchers at approve time without decrypting a second time.
 */
export async function decryptFile({
    body,
    iv,
    crypt,
    privateKey,
}: {
    body: ArrayBuffer
    iv: string
    crypt: string
    privateKey: ArrayBuffer
}): Promise<{ contents: ArrayBuffer; rawAesKey: ArrayBuffer }> {
    logger.info(`Decrypting file`)

    const { aesKey, rawAesKey } = await unwrapAesKey(crypt, privateKey)
    const contents = await decryptFileBody(body, Buffer.from(iv, 'base64'), aesKey)

    logger.info(`Finished decrypting file`)
    return { contents, rawAesKey }
}
