namespace ChatAIze.Passkeys.DataTransferObjects;

internal sealed record PasskeyCreationResult
{
    public required byte[] UserHandle { get; init; }

    public required byte[] CredentialId { get; init; }

    public required byte[] Attestation { get; init; }

    public required byte[] ClientDataJson { get; init; }
}
