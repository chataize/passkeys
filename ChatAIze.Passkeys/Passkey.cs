namespace ChatAIze.Passkeys;

public sealed record Passkey
{
    public required byte[] UserHandle { get; init; }

    public required byte[] CredentialId { get; init; }

    public byte[]? PublicKey { get; init; }

    public string UserHandleBase64 => Convert.ToBase64String(UserHandle);

    public string CredentialIdBase64 => Convert.ToBase64String(CredentialId);

    public string? PublicKeyBase64 => PublicKey is not null ? Convert.ToBase64String(PublicKey) : null;

    internal byte[]? Challenge { get; init; }

    internal byte[]? AuthenticatorData { get; init; }

    internal byte[]? ClientDataJson { get; init; }

    internal byte[]? Signature { get; init; }
}
