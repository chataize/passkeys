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
public sealed class PasskeyProvider(IOptions<PasskeyOptions> options, IJSRuntime jsRuntime) : IAsyncDisposable
{
    private readonly Lazy<Task<IJSObjectReference>> moduleTask = new(() => jsRuntime.InvokeAsync<IJSObjectReference>("import", "./_content/ChatAIze.Passkeys/passkeys.js").AsTask());

    public async ValueTask<Passkey?> CreatePasskeyAsync(string userId, string? userName = null, string? displayName = null)
    {
        try
        {
            var module = await moduleTask.Value;
            var challenge = RandomNumberGenerator.GetBytes(32);
            var passkeyCreationResult = await module.InvokeAsync<PasskeyCreationResult>("createPasskey", options.Value.Domain, options.Value.AppName, userId, userName ?? userId, displayName ?? userName ?? userId, challenge);

            var fido2Configuration = new Fido2Configuration
            {
                ServerDomain = options.Value.Domain,
                ServerName = options.Value.AppName,
                Origins = [.. options.Value.Origins]
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
                Id = Encoding.UTF8.GetBytes(userId),
                Name = userName ?? userId,
                DisplayName = displayName ?? userName ?? userId,
            };

            var credentialCreateOptions = new CredentialCreateOptions
            {
                Challenge = challenge,
                User = user,
                Rp = new PublicKeyCredentialRpEntity(fido2Configuration.ServerDomain, fido2Configuration.ServerName, null)
            };

            var credentialCreationResult = await fido2.MakeNewCredentialAsync(response, credentialCreateOptions, (_, _) => Task.FromResult(true));
            if (credentialCreationResult is null || credentialCreationResult.Result is null)
            {
                return null;
            }

            var passkey = new Passkey
            {
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

    public async ValueTask<Passkey?> GetPasskeyAsync()
    {
        try
        {
            var module = await moduleTask.Value;
            var challenge = RandomNumberGenerator.GetBytes(32);
            var result = await module.InvokeAsync<PasskeyRetrievalResult>("getPasskey", options.Value.Domain, challenge);

            var passkey = new Passkey
            {
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

    public async ValueTask<bool> VerifyPasskeyAsync(Passkey passkey, byte[] publicKey)
    {
        try
        {
            var fido2Configuration = new Fido2Configuration
            {
                ServerDomain = options.Value.Domain,
                ServerName = options.Value.AppName,
                Origins = [.. options.Value.Origins]
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

            var assertionResult = await fido2.MakeAssertionAsync(response, assertionOptions, publicKey, 0, (_, _) => Task.FromResult(true));

            return assertionResult.Status == "ok";
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
            var module = await moduleTask.Value;
            await module.DisposeAsync();
        }
    }
}
