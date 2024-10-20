namespace ChatAIze.Passkeys.DataTransferObjects;

internal sealed record PasskeyRetrievalResult
{
    public required string CredentialId { get; init; }

    public required string AuthenticatorData { get; init; }

    public required string ClientDataJson { get; init; }

    public required string Signature { get; init; }
}

