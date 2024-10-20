namespace ChatAIze.Passkeys;

public sealed record Passkey
{
    public required string CredentialId { get; set; }

    public byte[]? Challenge { get; set; }

    public string? AuthenticatorData { get; set; }

    public string? ClientDataJson { get; set; }

    public string? Signature { get; set; }

    public string? PublicKey { get; set; }
}
