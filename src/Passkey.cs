namespace ChatAIze.Passkeys;

public sealed record Passkey
{
    public required byte[]? CredentialId { get; set; }

    public byte[]? PublicKey { get; set; }

    public string? CredentialIdBase64 => CredentialId is not null ? Convert.ToBase64String(CredentialId) : null;

    public string? PublicKeyBase64 => PublicKey is not null ? Convert.ToBase64String(PublicKey) : null;

    public byte[]? Challenge { get; set; }

    internal byte[]? AuthenticatorData { get; set; }

    internal byte[]? ClientDataJson { get; set; }

    internal byte[]? Signature { get; set; }
}
