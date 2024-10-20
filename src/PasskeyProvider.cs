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
        var module = await moduleTask.Value;
        var challenge = RandomNumberGenerator.GetBytes(32);
        var passkeyCreationResult = await module.InvokeAsync<PasskeyCreationResult>("createPasskey", options.Value.Domain, options.Value.AppName, userId, userName ?? userId, displayName ?? userName ?? userId, challenge);
        var fido2Configuration = new Fido2Configuration
        {
            ServerDomain = options.Value.Domain,
            ServerName = options.Value.AppName,
            Origins = [.. options.Value.Origins],
        };

        var fido2 = new Fido2(fido2Configuration);

        var credentialIdBytes = Convert.FromBase64String(passkeyCreationResult.CredentialId);
        var attestationBytes = Convert.FromBase64String(passkeyCreationResult.Attestation);
        var clientDataJsonBytes = Convert.FromBase64String(passkeyCreationResult.ClientDataJson);

        var response = new AuthenticatorAttestationRawResponse
        {
            Id = credentialIdBytes,
            RawId = credentialIdBytes,
            Type = PublicKeyCredentialType.PublicKey,
            Response = new AuthenticatorAttestationRawResponse.ResponseData
            {
                AttestationObject = attestationBytes,
                ClientDataJson = clientDataJsonBytes,
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
            CredentialId = Convert.ToBase64String(credentialCreationResult.Result.CredentialId),
            PublicKey = Convert.ToBase64String(credentialCreationResult.Result.PublicKey),
        };

        return passkey;
    }

    public async ValueTask GetPasskeyAsync()
    {
        var module = await moduleTask.Value;
        await module.InvokeAsync<string>("getPasskey");
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
