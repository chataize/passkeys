export function arePasskeysSupported() {
    return !!(window.PublicKeyCredential &&
        navigator.credentials &&
        typeof navigator.credentials.create === 'function' &&
        typeof navigator.credentials.get === 'function');
}

function base64ToBytes(value) {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function toUint8Array(value) {
    if (value instanceof Uint8Array) {
        return value;
    }
    if (value instanceof ArrayBuffer) {
        return new Uint8Array(value);
    }
    if (ArrayBuffer.isView(value)) {
        return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    if (Array.isArray(value)) {
        return new Uint8Array(value);
    }
    if (typeof value === "string") {
        return base64ToBytes(value);
    }
    return new Uint8Array();
}

function toCredentialDescriptors(credentials) {
    if (!credentials || credentials.length === 0) {
        return undefined;
    }

    const descriptors = [];
    for (const credential of credentials) {
        const id = toUint8Array(credential);
        if (id.length > 0) {
            descriptors.push({ type: "public-key", id: id });
        }
    }

    return descriptors.length > 0 ? descriptors : undefined;
}

export async function createPasskey(domain, appName, userId, userName, userDisplayName, challenge, excludeCredentials) {
    const publicKey = {
        challenge: challenge,
        rp: {
            name: appName,
            id: domain
        },
        user: {
            id: userId,
            name: userName,
            displayName: userDisplayName
        },
        pubKeyCredParams: [
            { type: "public-key", alg: -7 },
            { type: "public-key", alg: -257 },
            { type: "public-key", alg: -8 }
        ],
    };
    const exclude = toCredentialDescriptors(excludeCredentials);
    if (exclude) {
        publicKey.excludeCredentials = exclude;
    }

    const credential = await navigator.credentials.create({ publicKey });

    return {
        credentialId: new Uint8Array(credential.rawId),
        attestation: new Uint8Array(credential.response.attestationObject),
        clientDataJSON: new Uint8Array(credential.response.clientDataJSON)
    };
}

export async function getPasskey(domain, challenge, allowCredentials) {
    const publicKey = { challenge: challenge, rpId: domain };
    const allow = toCredentialDescriptors(allowCredentials);
    if (allow) {
        publicKey.allowCredentials = allow;
    }
    const credential = await navigator.credentials.get({ publicKey });

    const userHandle = credential.response.userHandle
        ? new Uint8Array(credential.response.userHandle)
        : new Uint8Array();

    return {
        userHandle: userHandle,
        credentialId: new Uint8Array(credential.rawId),
        authenticatorData: new Uint8Array(credential.response.authenticatorData),
        clientDataJSON: new Uint8Array(credential.response.clientDataJSON),
        signature: new Uint8Array(credential.response.signature)
    };
}

