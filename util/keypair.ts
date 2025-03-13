export async function generateKeyPair(): Promise<{
    publicKey: CryptoKey,
    privateKey: CryptoKey,
    exportedPublicKey: ArrayBuffer,
    exportedPrivateKey: ArrayBuffer,
    publicKeyString: string,
    privateKeyString: string,
    fingerprint: string
}> {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: 2048,
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

    const fingerprint = await fingerprintFromPublicKey(publicKeyString)

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

// Helper: Convert an ArrayBuffer to a hex string.
export function arrayBufferToHex(buffer: ArrayBuffer) {
    const byteArray = new Uint8Array(buffer)
    return Array.from(byteArray)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
}

export async function fingerprintFromPublicKey(publicKey: string): Promise<string> {
    const publicKeyBuffer = pemToArrayBuffer(publicKey)

    // Import publicKey
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

    // Export the public key as SPKI (DER encoded)
    const spki = await crypto.subtle.exportKey('spki', publicKeyImported)

    // Compute the SHA‑256 digest (fingerprint) of the SPKI data
    const fingerprintBuffer = await crypto.subtle.digest('SHA-256', spki)

    // Convert the ArrayBuffer fingerprint into a hexadecimal string (colon-delimited)
    return arrayBufferToHex(fingerprintBuffer)
}

export async function privateKeyFromString(privateKey: string): Promise<CryptoKey> {
    const privateKeyBuffer = pemToArrayBuffer(privateKey)

    // Import the RSA private key.
    // Adjust the algorithm (e.g., "RSA-PSS", "RSA-OAEP") and usages as needed.
    return await crypto.subtle.importKey(
        'pkcs8',
        privateKeyBuffer,
        {
            name: 'RSA-PSS', // or "RSA-OAEP" depending on your key usage
            hash: 'SHA-256',
        },
        true, // Extractable - intended to be used with fingerprintFromPrivateKey
        ['sign'],
    )
}

export async function fingerprintFromPrivateKey(privateKey: CryptoKey | string): Promise<string> {
    if (typeof privateKey === 'string') {
        privateKey = await privateKeyFromString(privateKey)
    }

    // Export the private key as JWK to extract the public key parameters (n and e)
    const jwk = await crypto.subtle.exportKey('jwk', privateKey)

    // Create a JWK object for the public key using modulus (n) and exponent (e)
    const publicJwk = {
        kty: jwk.kty,
        n: jwk.n,
        e: jwk.e,
        alg: jwk.alg,
        ext: true,
    }

    // Import the public key
    const publicKey = await crypto.subtle.importKey(
        'jwk',
        publicJwk,
        {
            name: 'RSA-PSS', // ensure this matches the private key's algorithm
            hash: 'SHA-256',
        },
        true,
        ['verify'],
    )

    // Export the public key as SPKI (DER encoded)
    const spki = await crypto.subtle.exportKey('spki', publicKey)

    // Compute the SHA‑256 digest (fingerprint) of the SPKI data
    const fingerprintBuffer = await crypto.subtle.digest('SHA-256', spki)

    // Convert the ArrayBuffer fingerprint into a hexadecimal string (colon-delimited)
    return arrayBufferToHex(fingerprintBuffer)
}

