using System.Security.Cryptography;
using System.Text;
using ChatAIze.Passkeys.DataTransferObjects;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.JSInterop;

namespace ChatAIze.Passkeys;

[method: ActivatorUtilitiesConstructor]
public sealed class PasskeyProvider(IOptions<PasskeyOptions> globalOptions, IJSRuntime jsRuntime) : IAsyncDisposable
{
    // Lazily import the JS module so it is loaded only when first needed.
    private readonly Lazy<Task<IJSObjectReference>> moduleTask = new(() => jsRuntime.InvokeAsync<IJSObjectReference>("import", "./_content/ChatAIze.Passkeys/passkeys.js").AsTask());

    private readonly CancellationTokenSource _cancellationTokenSource = new();

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
    private static string ToBase64Url(byte[] data)
    {
        var base64 = Convert.ToBase64String(data);
        return base64.Replace("+", "-").Replace("/", "_").TrimEnd('=');
    }
}
