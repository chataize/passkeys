namespace ChatAIze.Passkeys.DataTransferObjects;

internal sealed record PasskeyCreationResult
{
    public required string CredentialId { get; init; }

    public required string Attestation { get; init; }

    public required string ClientDataJson { get; init; }
}
