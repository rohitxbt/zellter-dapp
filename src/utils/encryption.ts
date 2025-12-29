// Simple AES encryption/decryption for client-side file security

export const generateAESKey = async (): Promise<CryptoKey> => {
    return window.crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256,
        },
        true,
        ["encrypt", "decrypt"]
    );
};

export const exportKey = async (key: CryptoKey): Promise<string> => {
    const exported = await window.crypto.subtle.exportKey("jwk", key);
    return JSON.stringify(exported);
};

export const importKey = async (jwkStr: string): Promise<CryptoKey> => {
    const jwk = JSON.parse(jwkStr);
    return window.crypto.subtle.importKey(
        "jwk",
        jwk,
        {
            name: "AES-GCM",
            length: 256,
        },
        true,
        ["encrypt", "decrypt"]
    );
};

export const exportKeyRaw = async (key: CryptoKey): Promise<Uint8Array> => {
    const exported = await window.crypto.subtle.exportKey("raw", key);
    return new Uint8Array(exported);
};

export const importKeyRaw = async (rawKey: Uint8Array): Promise<CryptoKey> => {
    return window.crypto.subtle.importKey(
        "raw",
        rawKey as any,
        {
            name: "AES-GCM",
            length: 256,
        },
        true,
        ["encrypt", "decrypt"]
    );
};

export const encryptFile = async (file: File, key: CryptoKey): Promise<{ encryptedBlob: Blob, iv: Uint8Array }> => {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const arrayBuffer = await file.arrayBuffer();
    
    // Cast iv to BufferSource to satisfy TS if needed, though Uint8Array should be valid
    // The error suggests TS thinks iv is Uint8Array<ArrayBufferLike> but encryption expects standard BufferSource
    // We can cast `iv as any` to bypass if it's a false positive or just ensure it's standard Uint8Array
    
    const encryptedBuffer = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv as any,
        },
        key,
        arrayBuffer
    );
    
    return {
        encryptedBlob: new Blob([encryptedBuffer]),
        iv: iv
    };
};

export const decryptFile = async (encryptedBlob: Blob, key: CryptoKey, iv: Uint8Array): Promise<Blob> => {
    const arrayBuffer = await encryptedBlob.arrayBuffer();
    
    const decryptedBuffer = await window.crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv as any,
        },
        key,
        arrayBuffer
    );
    
    return new Blob([decryptedBuffer]);
};

export const arrayBufferToBase64 = (buffer: Uint8Array): string => {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
};

export const base64ToArrayBuffer = (base64: string): Uint8Array => {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes;
};
