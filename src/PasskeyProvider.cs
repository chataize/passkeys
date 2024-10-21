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
            return false;
        }
    }

    public async ValueTask<Passkey?> CreatePasskeyAsync(byte[] userId, string userName, string? displayName = null, PasskeyOptions? options = null, CancellationToken cancellationToken = default)
    {
        try
        {
            options ??= globalOptions.Value;
            cancellationToken = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _cancellationTokenSource.Token).Token;

            var module = await moduleTask.Value;
            var challenge = RandomNumberGenerator.GetBytes(32);
            var passkeyCreationResult = await module.InvokeAsync<PasskeyCreationResult>("createPasskey", cancellationToken, options.Domain, options.AppName, userId, userName, displayName ?? userName, challenge);

            var fido2Configuration = new Fido2Configuration
            {
                ServerDomain = options.Domain,
                ServerName = options.AppName,
                Origins = [.. options.Origins]
            };

            var fido2 = new Fido2(fido2Configuration);

            var response = new AuthenticatorAttestationRawResponse
            {
                Id = passkeyCreationResult.CredentialId,
                RawId = passkeyCreationResult.CredentialId,
                Type = PublicKeyCredentialType.PublicKey,
                Response = new AuthenticatorAttestationRawResponse.ResponseData
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
                Rp = new PublicKeyCredentialRpEntity(fido2Configuration.ServerDomain, fido2Configuration.ServerName, null)
            };

            var credentialCreationResult = await fido2.MakeNewCredentialAsync(response, credentialCreateOptions, (_, _) => Task.FromResult(true), cancellationToken: cancellationToken);
            if (credentialCreationResult is null || credentialCreationResult.Result is null)
            {
                return null;
            }

            var passkey = new Passkey
            {
                UserHandle = userId,
                CredentialId = credentialCreationResult.Result.CredentialId,
                PublicKey = credentialCreationResult.Result.PublicKey,
            };

            return passkey;
        }
        catch
        {
            return null;
        }
    }

    public async Task<Passkey?> CreatePasskeyAsync(string userId, string? userName = null, string? displayName = null, PasskeyOptions? options = null, CancellationToken cancellationToken = default)
    {
        try
        {
            return await CreatePasskeyAsync(Encoding.UTF8.GetBytes(userId), userName ?? userId, displayName ?? userName ?? userId, options, cancellationToken);
        }
        catch
        {
            return null;
        }
    }

    public async ValueTask<Passkey?> GetPasskeyAsync(PasskeyOptions? options = null, CancellationToken cancellationToken = default)
    {
        try
        {
            options ??= globalOptions.Value;
            cancellationToken = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _cancellationTokenSource.Token).Token;

            var module = await moduleTask.Value;
            var challenge = RandomNumberGenerator.GetBytes(32);
            var result = await module.InvokeAsync<PasskeyRetrievalResult>("getPasskey", cancellationToken, options.Domain, challenge);

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

    public async ValueTask<bool> VerifyPasskeyAsync(Passkey passkey, byte[] userHandle, byte[] publicKey, PasskeyOptions? options = null, CancellationToken cancellationToken = default)
    {
        try
        {
            options ??= globalOptions.Value;
            cancellationToken = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _cancellationTokenSource.Token).Token;

            var fido2Configuration = new Fido2Configuration
            {
                ServerDomain = options.Domain,
                ServerName = options.AppName,
                Origins = [.. options.Origins]
            };

            var fido2 = new Fido2(fido2Configuration);

            var response = new AuthenticatorAssertionRawResponse
            {
                Id = passkey.CredentialId,
                RawId = passkey.CredentialId,
                Type = PublicKeyCredentialType.PublicKey,
                Response = new AuthenticatorAssertionRawResponse.AssertionResponse
                {
                    AuthenticatorData = passkey.AuthenticatorData,
                    ClientDataJson = passkey.ClientDataJson,
                    Signature = passkey.Signature,
                }
            };

            var assertionOptions = new AssertionOptions
            {
                Challenge = passkey.Challenge,
                RpId = fido2Configuration.ServerDomain,
            };

            var assertionResult = await fido2.MakeAssertionAsync(response, assertionOptions, publicKey, 0, (args, _) => Task.FromResult(args.UserHandle == userHandle), cancellationToken: cancellationToken);
            return assertionResult.Status == "ok";
        }
        catch
        {
            return false;
        }
    }

    public async ValueTask<bool> VerifyPasskeyAsync(Passkey passkey, string userHandle, string publicKey, PasskeyOptions? options = null, CancellationToken cancellationToken = default)
    {
        try
        {
            return await VerifyPasskeyAsync(passkey, Convert.FromBase64String(userHandle), Convert.FromBase64String(publicKey), options, cancellationToken);
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
}
