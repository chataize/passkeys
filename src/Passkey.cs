namespace ChatAIze.Passkeys;

public sealed record Passkey
{
    public required byte[]? CredentialId { get; set; }

    public byte[]? Challenge { get; set; }

    public byte[]? AuthenticatorData { get; set; }

    public byte[]? ClientDataJson { get; set; }

    public byte[]? Signature { get; set; }

    public byte[]? PublicKey { get; set; }

    public string? CredentialIdBase64 => CredentialId is not null ? Convert.ToBase64String(CredentialId) : null;

    public string? PublicKeyBase64 => PublicKey is not null ? Convert.ToBase64String(PublicKey) : null;
}
