export async function generateKeyPair(): Promise<{
    publicKey: CryptoKey
    privateKey: CryptoKey
    exportedPublicKey: ArrayBuffer
    exportedPrivateKey: ArrayBuffer
    publicKeyString: string
    privateKeyString: string
    fingerprint: string
}> {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: 4096,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
        },
        true, // whether the key is extractable (i.e. can be used in exportKey)
        ['encrypt', 'decrypt'], // key usages
    )

    // Export the public key
    const exportedPublicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey)
    const publicKeyString = btoa(String.fromCharCode(...new Uint8Array(exportedPublicKey)))

    // Export the private key
    const exportedPrivateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey)
    const privateKeyString = btoa(String.fromCharCode(...new Uint8Array(exportedPrivateKey)))

    const fingerprint = await fingerprintKeyData(exportedPublicKey)

    // TODO Figure out what we want to export
    return {
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey,
        exportedPublicKey,
        exportedPrivateKey,
        publicKeyString,
        privateKeyString,
        fingerprint,
    }
}

export type SerializedBuffer = {
    type: 'Buffer'
    data: number[]
}

export function serializedBufferToArrayBuffer(input: SerializedBuffer): ArrayBuffer {
    return new Uint8Array(input.data).buffer
}

export async function serializedBufferToPublicKey(buffer: SerializedBuffer) {
    const publicKeyBuffer = serializedBufferToArrayBuffer(buffer)

    const publicKeyImported = await crypto.subtle.importKey(
        'spki',
        publicKeyBuffer,
        {
            name: 'RSA-OAEP',
            hash: 'SHA-256',
        },
        true,
        ['encrypt'],
    )
    return publicKeyImported
}

// Helper: Convert a PEM encoded string to an ArrayBuffer.
export function pemToArrayBuffer(pem: string) {
    // Remove the PEM header, footer, and line breaks.
    const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')
    // Use atob in the browser, or Buffer in Node.js.
    if (typeof atob === 'function') {
        const binaryStr = atob(b64)
        const len = binaryStr.length
        const bytes = new Uint8Array(len)
        for (let i = 0; i < len; i++) {
            bytes[i] = binaryStr.charCodeAt(i)
        }
        return bytes.buffer
    } else {
        return Buffer.from(b64, 'base64').buffer
    }
}

// Helper for testing: Convert an PEM key into the format that keys are tranfered as in API requests:
// { type: 'Buffer', data: [1,2,3,...] }
export function pemToJSONBuffer(pem: string): SerializedBuffer {
    return JSON.parse(JSON.stringify(Buffer.from(pemToArrayBuffer(pem))))
}

// Helper: Convert an ArrayBuffer to a hex string.
export function arrayBufferToHex(buffer: ArrayBuffer) {
    const byteArray = new Uint8Array(buffer)
    return Array.from(byteArray)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
}

export async function fingerprintKeyData(publicKeyBuffer: ArrayBuffer): Promise<string> {
    // Compute the SHA‑256 digest (fingerprint) of the SPKI data
    const fingerprintBuffer = await crypto.subtle.digest('SHA-256', publicKeyBuffer)

    // Convert the ArrayBuffer fingerprint into a hexadecimal string (colon-delimited)
    return arrayBufferToHex(fingerprintBuffer)
}

export async function privateKeyFromBuffer(privateKeyBuffer: ArrayBuffer): Promise<CryptoKey> {
    // Import the RSA private key.
    return await crypto.subtle.importKey(
        'pkcs8',
        privateKeyBuffer,
        {
            name: 'RSA-OAEP', // or "RSA-PSS" depending on your key usage
            hash: 'SHA-256',
        },
        true, // Extractable - intended to be used with fingerprintFromPrivateKey
        ['decrypt'],
    )
}

export async function fingerPrintPublicKeyFromPrivateKey(privateKey: CryptoKey) {
    // Export the private key as a JWK (JSON Web Key)
    const jwk = await crypto.subtle.exportKey('jwk', privateKey)

    // Create a public JWK by keeping only the public parts: the modulus (n) and exponent (e)
    const publicJwk = {
        kty: jwk.kty, // key type (should be "RSA")
        n: jwk.n, // modulus
        e: jwk.e, // public exponent
        alg: jwk.alg, // algorithm (e.g., "RSA-OAEP-256")
        ext: jwk.ext, // extractable flag
    }

    // Re-import the public JWK as a public CryptoKey
    const publicKey = await crypto.subtle.importKey(
        'jwk',
        publicJwk,
        { name: 'RSA-OAEP', hash: 'SHA-256' }, // Use your specific algorithm here
        true,
        ['encrypt'], // Set usages appropriate for your public key (e.g., "encrypt")
    )

    const pk = await crypto.subtle.exportKey('spki', publicKey)
    return await fingerprintKeyData(pk)
}
