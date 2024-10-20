export async function createPasskey(domain, appName, userId, userName, userDisplayName, challenge) {
    const encoder = new TextEncoder();
    const publicKey = {
        challenge: challenge,
        rp: {
            name: appName,
            id: domain
        },
        user: {
            id: encoder.encode(userId),
            name: userName,
            displayName: userDisplayName
        },
        pubKeyCredParams: [
            { type: "public-key", alg: -7 }
        ],
    };

    const credential = await navigator.credentials.create({ publicKey });
    const credentialId = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)));
    const attestationBase64 = btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject)));
    const clientDataJSON = btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON)));

    return {
        credentialId: credentialId,
        attestation: attestationBase64,
        clientDataJSON: clientDataJSON
    };
}

export async function getPasskey(domain, challenge) {
    const publicKey = { challenge: challenge, rpId: domain };
    const credential = await navigator.credentials.get({ publicKey });
    const credentialId = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)));
    const authenticatorData = btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData)));
    const clientDataJSON = btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON)));
    const signature = btoa(String.fromCharCode(...new Uint8Array(credential.response.signature)));

    return {
        credentialId: credentialId,
        authenticatorData: authenticatorData,
        clientDataJSON: clientDataJSON,
        signature: signature
    };
}
