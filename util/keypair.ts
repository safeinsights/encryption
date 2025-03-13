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
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
        },
        true, // whether the key is extractable (i.e. can be used in exportKey)
        ['encrypt', 'decrypt'], // key usages
    )

    // Export the public key
    const exportedPublicKey = await window.crypto.subtle.exportKey('spki', keyPair.publicKey)
    const publicKeyString = btoa(String.fromCharCode(...new Uint8Array(exportedPublicKey)))

    // Export the private key
    const exportedPrivateKey = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey)
    const privateKeyString = btoa(String.fromCharCode(...new Uint8Array(exportedPrivateKey)))

    const fingerprint = await createFingerprint(keyPair.publicKey)

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

export async function exportKey(key: CryptoKey, format: 'spki' | 'pkcs8'): Promise<ArrayBuffer> {
    return crypto.subtle.exportKey(format, key)
}

export async function createFingerprint(publicKey: CryptoKey): Promise<string> {
    const exportedKey = await exportKey(publicKey, 'spki')
    const hashBuffer = await crypto.subtle.digest('SHA-256', exportedKey)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('')
}
