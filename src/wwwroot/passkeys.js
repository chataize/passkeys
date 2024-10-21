export function arePasskeysSupported() {
    return !!(window.PublicKeyCredential && typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function');
}

export async function createPasskey(domain, appName, userId, userName, userDisplayName, challenge) {
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
            { type: "public-key", alg: -7 }
        ],
    };

    const credential = await navigator.credentials.create({ publicKey });

    return {
        credentialId: new Uint8Array(credential.rawId),
        attestation: new Uint8Array(credential.response.attestationObject),
        clientDataJSON: new Uint8Array(credential.response.clientDataJSON)
    };
}

export async function getPasskey(domain, challenge) {
    const publicKey = { challenge: challenge, rpId: domain };
    const credential = await navigator.credentials.get({ publicKey });

    return {
        credentialId: new Uint8Array(credential.rawId),
        authenticatorData: new Uint8Array(credential.response.authenticatorData),
        clientDataJSON: new Uint8Array(credential.response.clientDataJSON),
        signature: new Uint8Array(credential.response.signature)
    };
}
