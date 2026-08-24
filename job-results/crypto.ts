import { privateKeyFromBuffer } from '../util'
import type { CipherName } from './types'
import logger from '../lib/logger'

/**
 * Cipher the writer emits. Authenticated (AEAD): a tampered body, IV or AAD makes decrypt throw
 * instead of returning plausible garbage.
 */
export const CURRENT_CIPHER = 'AES-GCM' satisfies CipherName

/**
 * Cipher assumed when a manifest declares none. Unauthenticated and read-only — kept because
 * production archives written before the manifest carried a cipher field are encrypted with it.
 */
export const LEGACY_CIPHER = 'AES-CBC' satisfies CipherName

/** Manifest format written by the current writer: cipher-stamped, GCM, AAD-bound. */
export const MANIFEST_VERSION = 2

/** Version an absent `version` field implies: the original CBC format. */
export const LEGACY_MANIFEST_VERSION = 1

/** 96 bits — the IV size AES-GCM is specified and optimised for. CBC used 128. */
export const GCM_IV_BYTES = 12

/** Full-length authentication tag. */
export const GCM_TAG_BITS = 128

/** Namespaces the AAD so bytes bound here can never be mistaken for another protocol's. */
const AAD_CONTEXT = 'si-encryption/job-results'

/** Bumped only if the AAD *shape* changes; the manifest version tracks the container. */
const AAD_VERSION = 1

/**
 * Additional authenticated data binding one file body to the job and path it was written under.
 *
 * Fed to AES-GCM on both encrypt and decrypt, so a body cannot be moved to another path, spliced
 * into another job's archive, or have its manifest entry renamed without decryption failing —
 * none of which plain ciphertext integrity would catch, because RSA-OAEP key wrapping is a public
 * operation and an attacker holding a recipient's public key can rewrap freely.
 *
 * Encoded as a JSON array rather than a delimited string: array element order is guaranteed by the
 * spec, and JSON escaping keeps a path containing the delimiter from shifting the field boundaries.
 */
export function fileAdditionalData(jobId: string | undefined, path: string): Uint8Array {
    return new TextEncoder().encode(JSON.stringify([AAD_CONTEXT, AAD_VERSION, jobId ?? null, path]))
}

/** Per-cipher parameters for `crypto.subtle.encrypt`/`decrypt`. */
function cipherParams(cipher: CipherName, iv: BufferSource, additionalData?: Uint8Array) {
    return cipher === 'AES-GCM'
        ? { name: 'AES-GCM' as const, iv, additionalData, tagLength: GCM_TAG_BITS }
        : { name: 'AES-CBC' as const, iv }
}

/**
 * Unwrap a file's RSA-encrypted AES key. Returns the AES `CryptoKey` plus its raw bytes — re-wrap
 * needs the bytes to grant other recipients access (see {@link wrapAesKey}).
 *
 * `cipher` must match the manifest: a key imported for the wrong algorithm cannot decrypt.
 */
export async function unwrapAesKey(
    crypt: string,
    privateKey: ArrayBuffer,
    cipher: CipherName = LEGACY_CIPHER,
): Promise<{ aesKey: CryptoKey; rawAesKey: ArrayBuffer }> {
    const encryptedKey = Buffer.from(crypt, 'base64')

    const rawAesKey = await crypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        await privateKeyFromBuffer(privateKey),
        encryptedKey,
    )

    const aesKey = await crypto.subtle.importKey('raw', rawAesKey, { name: cipher }, false, ['decrypt'])

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

export type BodyCryptoOptions = {
    /** Defaults to {@link LEGACY_CIPHER} so pre-cipher-field callers keep their behaviour. */
    cipher?: CipherName
    /** Ignored under AES-CBC, which has no AAD. Build it with {@link fileAdditionalData}. */
    additionalData?: Uint8Array
}

/** Encrypt one file body. Under AES-GCM `additionalData` is authenticated alongside the ciphertext. */
export async function encryptFileBody(
    body: ArrayBuffer,
    iv: BufferSource,
    aesKey: CryptoKey,
    { cipher = LEGACY_CIPHER, additionalData }: BodyCryptoOptions = {},
): Promise<ArrayBuffer> {
    return crypto.subtle.encrypt(cipherParams(cipher, iv, additionalData), aesKey, body)
}

/**
 * Decrypt one file body.
 *
 * Under AES-GCM this rejects on any mismatch of ciphertext, IV, key or AAD. Under the legacy
 * AES-CBC path nothing is verified: a wrong-but-valid key usually trips PKCS#7 padding and throws,
 * but roughly one time in 256 it yields garbage with no error, and tampering is never detected.
 * Callers must not treat a CBC-decrypted body as trustworthy.
 */
export async function decryptFileBody(
    body: ArrayBuffer,
    iv: BufferSource,
    aesKey: CryptoKey,
    { cipher = LEGACY_CIPHER, additionalData }: BodyCryptoOptions = {},
): Promise<ArrayBuffer> {
    return crypto.subtle.decrypt(cipherParams(cipher, iv, additionalData), aesKey, body)
}

/**
 * Decrypt a standalone file body + metadata (vs {@link ResultsReader}'s zip iteration).
 * Returns the raw AES key too, so the caller can re-wrap without decrypting again.
 *
 * For an AES-GCM body, pass the `path` and `jobId` its manifest recorded — they are part of the
 * AAD, and decryption fails without them.
 */
export async function decryptFile({
    body,
    iv,
    crypt,
    privateKey,
    cipher = LEGACY_CIPHER,
    path,
    jobId,
}: {
    body: ArrayBuffer
    iv: string
    crypt: string
    privateKey: ArrayBuffer
    cipher?: CipherName
    path?: string
    jobId?: string
}): Promise<{ contents: ArrayBuffer; rawAesKey: ArrayBuffer }> {
    logger.info(`Decrypting file`)

    const { aesKey, rawAesKey } = await unwrapAesKey(crypt, privateKey, cipher)
    const contents = await decryptFileBody(body, Buffer.from(iv, 'base64'), aesKey, {
        cipher,
        additionalData: cipher === 'AES-GCM' ? fileAdditionalData(jobId, path ?? '') : undefined,
    })

    logger.info(`Finished decrypting file`)
    return { contents, rawAesKey }
}
