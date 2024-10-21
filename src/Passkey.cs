namespace ChatAIze.Passkeys;

public sealed record Passkey
{
    public required byte[]? CredentialId { get; init; }

    public byte[]? PublicKey { get; init; }

    public string? CredentialIdBase64 => CredentialId is not null ? Convert.ToBase64String(CredentialId) : null;

    public string? PublicKeyBase64 => PublicKey is not null ? Convert.ToBase64String(PublicKey) : null;

    internal byte[]? Challenge { get; init; }

    internal byte[]? AuthenticatorData { get; init; }

    internal byte[]? ClientDataJson { get; init; }

    internal byte[]? Signature { get; init; }
}
