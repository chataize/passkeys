# Passkeys

C# .NET Blazor Server library for WebAuthn passkeys. It wraps the browser WebAuthn API and
FIDO2 verification so you can focus on storage and your sign-in flow.

## Contents

- [Features](#features)
- [Supported authenticators](#supported-authenticators)
- [Requirements and limitations](#requirements-and-limitations)
- [Install](#install)
- [Basic setup (Blazor Server)](#basic-setup-blazor-server)
- [Data you must store](#data-you-must-store)
- [Registration flow](#registration-flow)
- [Authentication flow](#authentication-flow)
- [Conditional mediation (autofill)](#conditional-mediation-autofill)
- [API reference](#api-reference)
- [Encoding notes](#encoding-notes)
- [Best practices](#best-practices)
- [Security considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Preview project](#preview-project)
- [License](#license)

## Features

- Register passkeys via the browser WebAuthn API
- Authenticate using passkey assertions
- Server-side verification using FIDO2 (Fido2NetLib)
- Conditional mediation (passkey autofill) support
- Allow/exclude credential lists for security keys and non-discoverable credentials
- Works with platform passkeys, synced passkeys, password manager passkeys, and external security keys
- Convenience base64 helpers on the `Passkey` model

## Supported authenticators

- Platform authenticators (Windows Hello, Touch ID, Face ID)
- Synced passkeys (iCloud Keychain, Google Password Manager, etc)
- Password manager passkeys (1Password, Bitwarden, etc)
- External security keys (USB/NFC/Bluetooth)

## Requirements and limitations

- Targets `net10.0`. Your app must run on .NET 10 or you must retarget the library.
- Designed for Blazor Server. Verification is server-side and not meant for Blazor WebAssembly.
- WebAuthn requires HTTPS or localhost. HTTP on public hosts will not work.
- The rpId (`PasskeyOptions.Domain`) must match the effective domain of the origin.
- `PasskeyProvider` returns `null`/`false` on failure and suppresses exceptions by design.
  Wrap calls and log state if you need diagnostics.
- Signature counters are not persisted; clone detection is not implemented.
- Advanced WebAuthn options (user verification, resident key, attestation preference,
  authenticator attachment, timeout, extensions, hints) are not exposed yet.
- All WebAuthn calls must happen after the component is interactive. In Blazor Server,
  call from `OnAfterRenderAsync` or UI event handlers, not during prerender.

## Install

```bash
dotnet add package ChatAIze.Passkeys --version 0.2.8
```

## Basic setup (Blazor Server)

Register the provider in `Program.cs`:

```csharp
using ChatAIze.Passkeys;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddPasskeyProvider(options =>
{
    options.Domain = "example.com"; // rpId, no scheme
    options.AppName = "Example";    // display name shown to users
    options.Origins = new List<string>
    {
        "https://example.com"
    };
});

var app = builder.Build();
app.UseStaticFiles(); // Required for the JS module in _content/ChatAIze.Passkeys
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();
app.Run();
```

Optional: add `@using ChatAIze.Passkeys` in `_Imports.razor` to simplify component code.

The JS module is loaded via dynamic import, so you do not need to add script tags manually.

### Notes on options

- `Domain` must be a registrable domain (no scheme, path, or port). Example: `example.com`.
- `Origins` must include the exact origin (scheme + host + port) of your app.
  Example: `https://example.com` or `https://localhost:7238`.
- If the origin does not match, WebAuthn verification will fail.

## Data you must store

For each credential, store:

- User handle (`Passkey.UserHandle`)
- Credential ID (`Passkey.CredentialId`)
- Public key (`Passkey.PublicKey`)

Optional but recommended:

- Signature counter (not handled by this library yet)
- Friendly name or device label
- Creation time and last-used time

A simple schema might look like:

- `UserId`
- `UserHandle` (bytes, <= 64 bytes recommended)
- `CredentialId` (bytes)
- `PublicKey` (bytes)
- `SignCount` (uint, optional)
- `DisplayName` (string, optional)

Store multiple credentials per user to support multiple devices.

## Registration flow

This flow is typically done after a user has authenticated with another method.

```csharp
@inject PasskeyProvider PasskeyProvider

@code {
    private async Task RegisterPasskeyAsync()
    {
        var userId = "user-123"; // stable, opaque identifier
        var existingCredentialIds = await credentialStore.GetCredentialIdsAsync(userId);

        var passkey = await PasskeyProvider.CreatePasskeyAsync(
            userId,
            userName: "user@example.com",
            displayName: "Example User",
            excludeCredentials: existingCredentialIds);

        if (passkey is null)
        {
            // Registration failed or was cancelled
            return;
        }

        await credentialStore.SaveAsync(new StoredCredential
        {
            UserId = userId,
            UserHandle = passkey.UserHandle,
            CredentialId = passkey.CredentialId,
            PublicKey = passkey.PublicKey!
        });
    }
}
```

### Why exclude credentials?

Use `excludeCredentials` to prevent registering the same authenticator more than once.
This helps avoid duplicate credentials when the user retries registration.

### User handle best practice

Use a stable, opaque identifier (database ID, GUID, etc). Do not use email addresses
or other user-visible data. Keep the byte length small (<= 64 bytes recommended).

## Authentication flow

### Discoverable credentials (platform passkeys, synced passkeys)

If you expect discoverable credentials, you can let the browser choose:

```csharp
@inject PasskeyProvider PasskeyProvider

@code {
    private async Task SignInAsync()
    {
        var passkey = await PasskeyProvider.GetPasskeyAsync();
        if (passkey is null)
        {
            return; // cancelled or failed
        }

        var user = await credentialStore.FindByCredentialIdAsync(passkey.CredentialId);
        if (user is null)
        {
            return; // unknown credential
        }

        var ok = await PasskeyProvider.VerifyPasskeyAsync(
            passkey,
            user.UserHandle,
            user.PublicKey);

        if (!ok)
        {
            return; // verification failed
        }

        // Sign in user
    }
}
```

### Non-discoverable credentials (security keys)

For security keys, provide `allowCredentials`:

```csharp
var allowCredentials = await credentialStore.GetCredentialIdsAsync(userId);

var passkey = await PasskeyProvider.GetPasskeyAsync(allowCredentials: allowCredentials);
if (passkey is null)
{
    return;
}

var ok = await PasskeyProvider.VerifyPasskeyAsync(
    passkey,
    storedUserHandle,
    storedPublicKey);
```

If the browser returns an empty user handle, resolve the user by `CredentialId` and
use that stored user handle for verification.

## Conditional mediation (autofill)

Conditional mediation surfaces passkeys in the browser autofill UI. In Blazor Server,
call it after the component renders and ensure an input with
`autocomplete="username webauthn"` exists.

```razor
<input @bind="_username" autocomplete="username webauthn" placeholder="Username" />
```

```csharp
protected override async Task OnAfterRenderAsync(bool firstRender)
{
    if (!firstRender)
    {
        return;
    }

    var available = await PasskeyProvider.IsConditionalMediationAvailableAsync();
    if (!available)
    {
        return;
    }

    var passkey = await PasskeyProvider.GetPasskeyConditionalAsync();
    if (passkey is null)
    {
        return; // user did not pick a credential
    }

    var user = await credentialStore.FindByCredentialIdAsync(passkey.CredentialId);
    if (user is null)
    {
        return;
    }

    var ok = await PasskeyProvider.VerifyPasskeyAsync(passkey, user.UserHandle, user.PublicKey);
    if (!ok)
    {
        return;
    }

    // Sign in user
}
```

### Conditional mediation tips

- Trigger it once after render; do not spam the call.
- Keep a fallback sign-in button for browsers that do not support it.
- In some browsers, the user must focus an input to see the autofill UI.

## API reference

### PasskeyProvider

#### ArePasskeysSupportedAsync

```csharp
ValueTask<bool> ArePasskeysSupportedAsync(CancellationToken cancellationToken = default)
```

Checks if the browser has the WebAuthn APIs. Returns `false` if JS interop is unavailable
or the app is not running in a browser.

#### IsConditionalMediationAvailableAsync

```csharp
ValueTask<bool> IsConditionalMediationAvailableAsync(CancellationToken cancellationToken = default)
```

Checks if conditional mediation is available for passkey autofill.

#### CreatePasskeyAsync

```csharp
ValueTask<Passkey?> CreatePasskeyAsync(
    byte[] userId,
    string userName,
    string? displayName = null,
    PasskeyOptions? options = null,
    IReadOnlyCollection<byte[]>? excludeCredentials = null,
    CancellationToken cancellationToken = default)
```

Overloads accept `string` or `Guid` user IDs. `userId` should be a stable, opaque identifier.
The returned `Passkey.PublicKey` should be stored for future verification.

#### GetPasskeyAsync

```csharp
ValueTask<Passkey?> GetPasskeyAsync(
    PasskeyOptions? options = null,
    IReadOnlyCollection<byte[]>? allowCredentials = null,
    CancellationToken cancellationToken = default)
```

Use `allowCredentials` for security keys and other non-discoverable credentials.

#### GetPasskeyConditionalAsync

```csharp
ValueTask<Passkey?> GetPasskeyConditionalAsync(
    PasskeyOptions? options = null,
    IReadOnlyCollection<byte[]>? allowCredentials = null,
    CancellationToken cancellationToken = default)
```

Starts conditional mediation (passkey autofill). Returns `null` if the user does not pick
a credential.

#### VerifyPasskeyAsync

```csharp
ValueTask<bool> VerifyPasskeyAsync(
    Passkey passkey,
    byte[] userId,
    byte[] publicKey,
    PasskeyOptions? options = null,
    CancellationToken cancellationToken = default)
```

Overloads accept `string` or `Guid` user IDs and base64 public keys. The public key
must be standard base64 (not base64url).

### Passkey

`Passkey` combines registration data (credential ID/public key) and assertion data
(authenticator response fields). Only `UserHandle`, `CredentialId`, and `PublicKey`
should be persisted; assertion fields are transient.

- `UserHandle` (byte[])
- `CredentialId` (byte[])
- `PublicKey` (byte[]?)
- `UserHandleBase64`, `CredentialIdBase64`, `PublicKeyBase64` (standard base64 helpers)

### PasskeyOptions

- `AppName`: relying party display name shown to users
- `Domain`: rpId (registrable domain, no scheme)
- `Origins`: exact allowed origins (scheme + host + port)

## Encoding notes

- The library exposes raw byte arrays for credential IDs and public keys.
- `Passkey.*Base64` helpers use standard base64. If you store base64url, convert accordingly.
- When passing `allowCredentials` or `excludeCredentials`, supply byte arrays. If you store
  values as strings, decode them with `Convert.FromBase64String`.

## Best practices

- Use a stable, opaque user handle rather than an email address.
- Always verify on the server; never trust client-provided claims.
- Prefer discoverable credentials for passwordless UX, and allow security keys via `allowCredentials`.
- Keep rpId and allowed origins consistent across environments.
- Use HTTPS in production. WebAuthn will not work on insecure origins.
- Store multiple credentials per user to support multiple devices.
- Provide a fallback sign-in method for unsupported browsers or user cancellations.

## Security considerations

- Treat credential IDs and public keys as sensitive metadata. Do not log them in production.
- If you do not persist signature counters, you lose clone detection. Consider extending
  verification with counters in your own storage layer.
- Attestation trust is not configured. If you require strict attestation or metadata
  validation, extend the library to integrate a metadata service and attestation checks.

## Troubleshooting

- **NotAllowedError**: user cancelled, device not available, or request timed out.
- **InvalidStateError**: credential already exists; use `excludeCredentials`.
- **SecurityError**: rpId or origin mismatch; check `PasskeyOptions.Domain` and `Origins`.
- **Passkeys Supported = false**: JS interop not ready or not running in a browser.
- **Conditional mediation never returns**: call after render and ensure input has
  `autocomplete="username webauthn"`.

## Preview project

The repository includes a preview app in `ChatAIze.Passkeys.Preview` that demonstrates:

- Registration
- Authentication
- Conditional mediation

Run it locally and update `PasskeyOptions` to match your local URLs.

## License

GPL-3.0-or-later
