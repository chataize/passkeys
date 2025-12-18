using System.Security.Cryptography;
using System.Text;
using ChatAIze.Passkeys.DataTransferObjects;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.JSInterop;

namespace ChatAIze.Passkeys;

/// <summary>
/// Provides passkey creation, retrieval, and verification using WebAuthn/FIDO2.
/// </summary>
/// <param name="globalOptions">The configured passkey options.</param>
/// <param name="jsRuntime">The JS runtime used for WebAuthn interop.</param>
/// <remarks>
/// <para>
/// WebAuthn requires a secure context (HTTPS) or <c>localhost</c>. If calls fail, verify the
/// origin, rpId, and that the component has rendered before invoking JS interop.
/// </para>
/// <para>
/// These APIs return <c>null</c>/<c>false</c> on errors; log and handle failures in callers
/// if you need diagnostics.
/// </para>
/// </remarks>
[method: ActivatorUtilitiesConstructor]
public sealed class PasskeyProvider(IOptions<PasskeyOptions> globalOptions, IJSRuntime jsRuntime) : IAsyncDisposable
{
    /// <summary>
    /// Lazily imports the JS module so it is loaded only when first needed.
    /// </summary>
    private readonly Lazy<Task<IJSObjectReference>> moduleTask = new(() => jsRuntime.InvokeAsync<IJSObjectReference>("import", "./_content/ChatAIze.Passkeys/passkeys.js").AsTask());

    /// <summary>
    /// Cancels in-flight operations when the provider is disposed.
    /// </summary>
    private readonly CancellationTokenSource _cancellationTokenSource = new();

    /// <summary>
    /// Checks whether passkeys are supported in the current browser environment.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns><c>true</c> when passkeys are supported; otherwise <c>false</c>.</returns>
    /// <remarks>
    /// A return value of <c>false</c> can also mean the code is running outside a browser
    /// or that JS interop is unavailable.
    /// </remarks>
    public async ValueTask<bool> ArePasskeysSupportedAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var module = await moduleTask.Value;
            return await module.InvokeAsync<bool>("arePasskeysSupported", cancellationToken);
        }
        catch
        {
            // If JS interop fails (e.g., not running in a browser), treat as unsupported.
            return false;
        }
    }

    /// <summary>
    /// Checks whether conditional mediation (passkey autofill) is available.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns><c>true</c> when conditional mediation is available; otherwise <c>false</c>.</returns>
    /// <remarks>
    /// Conditional mediation should be triggered only after the UI renders and typically
    /// requires an input with <c>autocomplete="username webauthn"</c>.
    /// </remarks>
    public async ValueTask<bool> IsConditionalMediationAvailableAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var module = await moduleTask.Value;
            return await module.InvokeAsync<bool>("isConditionalMediationAvailable", cancellationToken);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Creates a new passkey for the specified user.
    /// </summary>
    /// <param name="userId">The user handle bytes.</param>
    /// <param name="userName">The user name.</param>
    /// <param name="displayName">The user display name.</param>
    /// <param name="options">Optional passkey options; defaults to configured options.</param>
    /// <param name="excludeCredentials">Optional credential IDs to exclude from registration.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The created passkey, or <c>null</c> on failure.</returns>
    /// <remarks>
    /// The returned passkey includes the public key which you should persist for future verification.
    /// Use <paramref name="excludeCredentials"/> to prevent duplicate registrations on the same authenticator.
    /// Prefer a stable, opaque user handle (not an email address) for <paramref name="userId"/>.
    /// </remarks>
    public async ValueTask<Passkey?> CreatePasskeyAsync(byte[] userId, string userName, string? displayName = null, PasskeyOptions? options = null, IReadOnlyCollection<byte[]>? excludeCredentials = null, CancellationToken cancellationToken = default)
    {
        try
        {
            options ??= globalOptions.Value;
            // Link cancellation to provider lifetime so calls stop when the provider is disposed.
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _cancellationTokenSource.Token);
            cancellationToken = linkedCts.Token;

            var module = await moduleTask.Value;
            // The challenge is generated server-side and mirrored in the Fido2 verification step.
            var challenge = RandomNumberGenerator.GetBytes(32);
            var passkeyCreationResult = await module.InvokeAsync<PasskeyCreationResult>("createPasskey", cancellationToken, options.Domain, options.AppName, userId, userName, displayName ?? userName, challenge, excludeCredentials);

            var fido2Configuration = new Fido2Configuration
            {
                ServerDomain = options.Domain,
                ServerName = options.AppName,
                // Fido2 expects a set of allowed origins for client data validation.
                Origins = new HashSet<string>(options.Origins)
            };

            var fido2 = new Fido2(fido2Configuration);

            // Map the browser attestation response into the Fido2 expected shape.
            var response = new AuthenticatorAttestationRawResponse
            {
                Id = ToBase64Url(passkeyCreationResult.CredentialId),
                RawId = passkeyCreationResult.CredentialId,
                Type = PublicKeyCredentialType.PublicKey,
                Response = new AuthenticatorAttestationRawResponse.AttestationResponse
                {
                    AttestationObject = passkeyCreationResult.Attestation,
                    ClientDataJson = passkeyCreationResult.ClientDataJson,
                }
            };

            var user = new Fido2User
            {
                Id = userId,
                Name = userName,
                DisplayName = displayName ?? userName,
            };

            var credentialCreateOptions = new CredentialCreateOptions
            {
                Challenge = challenge,
                User = user,
                Rp = new PublicKeyCredentialRpEntity(fido2Configuration.ServerDomain, fido2Configuration.ServerName, null),
                PubKeyCredParams = new[]
                {
                    new PubKeyCredParam(COSE.Algorithm.ES256, PublicKeyCredentialType.PublicKey),
                    new PubKeyCredParam(COSE.Algorithm.RS256, PublicKeyCredentialType.PublicKey),
                    new PubKeyCredParam(COSE.Algorithm.EdDSA, PublicKeyCredentialType.PublicKey)
                }
            };
            // Exclude existing credentials to prevent duplicate registrations.
            if (excludeCredentials is { Count: > 0 })
            {
                credentialCreateOptions.ExcludeCredentials = excludeCredentials
                    .Where(id => id is { Length: > 0 })
                    .Select(id => new PublicKeyCredentialDescriptor(id))
                    .ToArray();
            }

            // We validate the attestation locally to extract the credential public key.
            var credentialCreationResult = await fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
            {
                AttestationResponse = response,
                OriginalOptions = credentialCreateOptions,
                IsCredentialIdUniqueToUserCallback = (_, _) => Task.FromResult(true),
            }, cancellationToken);
            if (credentialCreationResult is null)
            {
                return null;
            }

            var passkey = new Passkey
            {
                UserHandle = userId,
                CredentialId = credentialCreationResult.Id,
                PublicKey = credentialCreationResult.PublicKey,
            };

            return passkey;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Creates a new passkey for the specified user.
    /// </summary>
    /// <param name="userId">The user identifier string.</param>
    /// <param name="userName">The user name.</param>
    /// <param name="displayName">The user display name.</param>
    /// <param name="options">Optional passkey options; defaults to configured options.</param>
    /// <param name="excludeCredentials">Optional credential IDs to exclude from registration.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The created passkey, or <c>null</c> on failure.</returns>
    /// <remarks>
    /// This overload encodes the user identifier as UTF-8 bytes for the user handle.
    /// </remarks>
    public async Task<Passkey?> CreatePasskeyAsync(string userId, string? userName = null, string? displayName = null, PasskeyOptions? options = null, IReadOnlyCollection<byte[]>? excludeCredentials = null, CancellationToken cancellationToken = default)
    {
        try
        {
            return await CreatePasskeyAsync(Encoding.UTF8.GetBytes(userId), userName ?? userId, displayName ?? userName ?? userId, options: options, excludeCredentials: excludeCredentials, cancellationToken: cancellationToken);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Creates a new passkey for the specified user.
    /// </summary>
    /// <param name="userId">The user identifier.</param>
    /// <param name="userName">The user name.</param>
    /// <param name="displayName">The user display name.</param>
    /// <param name="options">Optional passkey options; defaults to configured options.</param>
    /// <param name="excludeCredentials">Optional credential IDs to exclude from registration.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The created passkey, or <c>null</c> on failure.</returns>
    /// <remarks>
    /// This overload encodes the Guid as a string for the user handle.
    /// </remarks>
    public async Task<Passkey?> CreatePasskeyAsync(Guid userId, string? userName = null, string? displayName = null, PasskeyOptions? options = null, IReadOnlyCollection<byte[]>? excludeCredentials = null, CancellationToken cancellationToken = default)
    {
        try
        {
            var userIdString = userId.ToString();
            return await CreatePasskeyAsync(userIdString, userName, displayName, options: options, excludeCredentials: excludeCredentials, cancellationToken: cancellationToken);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Requests an assertion for an existing passkey.
    /// </summary>
    /// <param name="options">Optional passkey options; defaults to configured options.</param>
    /// <param name="allowCredentials">Optional credential IDs to allow for assertion.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The asserted passkey, or <c>null</c> on failure.</returns>
    /// <remarks>
    /// For security keys or other non-discoverable credentials, supply <paramref name="allowCredentials"/>.
    /// For discoverable passkeys, you can omit it and let the browser choose.
    /// </remarks>
    public async ValueTask<Passkey?> GetPasskeyAsync(PasskeyOptions? options = null, IReadOnlyCollection<byte[]>? allowCredentials = null, CancellationToken cancellationToken = default)
    {
        try
        {
            options ??= globalOptions.Value;
            // Link cancellation to provider lifetime so calls stop when the provider is disposed.
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _cancellationTokenSource.Token);
            cancellationToken = linkedCts.Token;

            var module = await moduleTask.Value;
            var challenge = RandomNumberGenerator.GetBytes(32);
            // AllowCredentials limits the acceptable credentials for non-discoverable flows.
            var result = await module.InvokeAsync<PasskeyRetrievalResult>("getPasskey", cancellationToken, options.Domain, challenge, allowCredentials);

            var passkey = new Passkey
            {
                UserHandle = result.UserHandle,
                CredentialId = result.CredentialId,
                Challenge = challenge,
                AuthenticatorData = result.AuthenticatorData,
                ClientDataJson = result.ClientDataJson,
                Signature = result.Signature
            };

            return passkey;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Requests an assertion using conditional mediation (passkey autofill).
    /// </summary>
    /// <param name="options">Optional passkey options; defaults to configured options.</param>
    /// <param name="allowCredentials">Optional credential IDs to allow for assertion.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The asserted passkey, or <c>null</c> when no credential is selected.</returns>
    /// <remarks>
    /// Call this after the page has rendered. Conditional mediation typically requires an
    /// input element with <c>autocomplete="username webauthn"</c> to surface the autofill UI.
    /// </remarks>
    public async ValueTask<Passkey?> GetPasskeyConditionalAsync(PasskeyOptions? options = null, IReadOnlyCollection<byte[]>? allowCredentials = null, CancellationToken cancellationToken = default)
    {
        try
        {
            options ??= globalOptions.Value;
            // Link cancellation to provider lifetime so calls stop when the provider is disposed.
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _cancellationTokenSource.Token);
            cancellationToken = linkedCts.Token;

            var module = await moduleTask.Value;
            var challenge = RandomNumberGenerator.GetBytes(32);
            // AllowCredentials limits the acceptable credentials for conditional UI as well.
            var result = await module.InvokeAsync<PasskeyRetrievalResult?>("getPasskeyConditional", cancellationToken, options.Domain, challenge, allowCredentials);
            // Conditional mediation returns null when the user does not pick a credential.
            if (result is null)
            {
                return null;
            }

            var passkey = new Passkey
            {
                UserHandle = result.UserHandle,
                CredentialId = result.CredentialId,
                Challenge = challenge,
                AuthenticatorData = result.AuthenticatorData,
                ClientDataJson = result.ClientDataJson,
                Signature = result.Signature
            };

            return passkey;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Verifies an asserted passkey against stored user and credential data.
    /// </summary>
    /// <param name="passkey">The asserted passkey.</param>
    /// <param name="userId">The expected user handle bytes.</param>
    /// <param name="publicKey">The stored credential public key.</param>
    /// <param name="options">Optional passkey options; defaults to configured options.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns><c>true</c> when verification succeeds; otherwise <c>false</c>.</returns>
    /// <remarks>
    /// This library does not persist the signature counter; it always passes <c>0</c>.
    /// If you need clone detection, persist and supply the stored counter yourself.
    /// For non-discoverable credentials, resolve the user by credential ID if the user handle is empty.
    /// </remarks>
    public async ValueTask<bool> VerifyPasskeyAsync(Passkey passkey, byte[] userId, byte[] publicKey, PasskeyOptions? options = null, CancellationToken cancellationToken = default)
    {
        try
        {
            options ??= globalOptions.Value;
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _cancellationTokenSource.Token);
            cancellationToken = linkedCts.Token;

            var fido2Configuration = new Fido2Configuration
            {
                ServerDomain = options.Domain,
                ServerName = options.AppName,
                Origins = new HashSet<string>(options.Origins)
            };

            var fido2 = new Fido2(fido2Configuration);

            // Abort early if required assertion fields are missing.
            if (passkey.AuthenticatorData is null || passkey.ClientDataJson is null || passkey.Signature is null || passkey.Challenge is null)
            {
                return false;
            }

            var response = new AuthenticatorAssertionRawResponse
            {
                Id = ToBase64Url(passkey.CredentialId),
                RawId = passkey.CredentialId,
                Type = PublicKeyCredentialType.PublicKey,
                Response = new AuthenticatorAssertionRawResponse.AssertionResponse
                {
                    AuthenticatorData = passkey.AuthenticatorData,
                    ClientDataJson = passkey.ClientDataJson,
                    Signature = passkey.Signature,
                    UserHandle = passkey.UserHandle,
                }
            };

            var assertionOptions = new AssertionOptions
            {
                Challenge = passkey.Challenge,
                RpId = fido2Configuration.ServerDomain,
            };

            // StoredSignatureCounter is not persisted by this library, so we pass 0.
            var assertionResult = await fido2.MakeAssertionAsync(new MakeAssertionParams
            {
                AssertionResponse = response,
                OriginalOptions = assertionOptions,
                StoredPublicKey = publicKey,
                StoredSignatureCounter = 0,
                IsUserHandleOwnerOfCredentialIdCallback = (args, _) => Task.FromResult(args.UserHandle.AsSpan().SequenceEqual(userId)),
            }, cancellationToken);
            return assertionResult is not null;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Verifies an asserted passkey using string inputs.
    /// </summary>
    /// <param name="passkey">The asserted passkey.</param>
    /// <param name="userId">The expected user handle string.</param>
    /// <param name="publicKey">The stored credential public key as base64.</param>
    /// <param name="options">Optional passkey options; defaults to configured options.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns><c>true</c> when verification succeeds; otherwise <c>false</c>.</returns>
    /// <remarks>
    /// The <paramref name="publicKey"/> value must be standard base64 (not base64url).
    /// </remarks>
    public async ValueTask<bool> VerifyPasskeyAsync(Passkey passkey, string userId, string publicKey, PasskeyOptions? options = null, CancellationToken cancellationToken = default)
    {
        try
        {
            return await VerifyPasskeyAsync(passkey, Encoding.UTF8.GetBytes(userId), Convert.FromBase64String(publicKey), options, cancellationToken);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Verifies an asserted passkey using a Guid user identifier.
    /// </summary>
    /// <param name="passkey">The asserted passkey.</param>
    /// <param name="userId">The expected user identifier.</param>
    /// <param name="publicKey">The stored credential public key as base64.</param>
    /// <param name="options">Optional passkey options; defaults to configured options.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns><c>true</c> when verification succeeds; otherwise <c>false</c>.</returns>
    /// <remarks>
    /// The <paramref name="publicKey"/> value must be standard base64 (not base64url).
    /// </remarks>
    public async ValueTask<bool> VerifyPasskeyAsync(Passkey passkey, Guid userId, string publicKey, PasskeyOptions? options = null, CancellationToken cancellationToken = default)
    {
        try
        {
            return await VerifyPasskeyAsync(passkey, userId.ToString(), publicKey, options, cancellationToken);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Disposes the JS module and cancels any in-flight operations.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (moduleTask.IsValueCreated)
        {
            if (!_cancellationTokenSource.IsCancellationRequested && _cancellationTokenSource.Token.CanBeCanceled)
            {
                await _cancellationTokenSource.CancelAsync();
                _cancellationTokenSource.Dispose();
            }

            var module = await moduleTask.Value;
            await module.DisposeAsync();
        }
    }

    // WebAuthn expects base64url for Id fields.
    /// <summary>
    /// Encodes bytes using base64url for WebAuthn IDs.
    /// </summary>
    /// <param name="data">The bytes to encode.</param>
    /// <returns>A base64url string.</returns>
    /// <remarks>
    /// WebAuthn expects base64url for credential IDs when represented as strings.
    /// </remarks>
    private static string ToBase64Url(byte[] data)
    {
        var base64 = Convert.ToBase64String(data);
        return base64.Replace("+", "-").Replace("/", "_").TrimEnd('=');
    }
}
