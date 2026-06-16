import { privateKeyFromBuffer } from '../util'
import logger from '../lib/logger'

/**
 * Unwrap a file's RSA-encrypted AES key. Returns the AES `CryptoKey` plus its raw
 * bytes — re-wrap needs the bytes to grant other recipients access (see {@link wrapAesKey}).
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

    const aesKey = await crypto.subtle.importKey('raw', rawAesKey, { name: 'AES-CBC' }, false, ['decrypt'])

    return { aesKey, rawAesKey }
}

/** Re-wrap a raw AES key for a recipient's RSA public key. Body and IV are untouched. */
export async function wrapAesKey(rawAesKey: ArrayBuffer, publicKey: ArrayBuffer): Promise<string> {
    const key = await crypto.subtle.importKey('spki', publicKey, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, [
        'encrypt',
    ])

    const encryptedKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, rawAesKey)

    return Buffer.from(encryptedKey).toString('base64')
}

export async function decryptFileBody(body: ArrayBuffer, iv: BufferSource, aesKey: CryptoKey): Promise<ArrayBuffer> {
    return crypto.subtle.decrypt({ name: 'AES-CBC', iv }, aesKey, body)
}

/**
 * Decrypt a standalone file body + metadata (vs {@link ResultsReader}'s zip iteration).
 * Returns the raw AES key too, so the caller can re-wrap without decrypting again.
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
