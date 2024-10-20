namespace ChatAIze.Passkeys;

public sealed record Passkey
{
    public required string CredentialId { get; set; }

    public string? PublicKey { get; set; }
}
