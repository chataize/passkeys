namespace ChatAIze.Passkeys.DataTransferObjects;

internal sealed record PasskeyCreationResult
{
    internal required byte[] CredentialId { get; init; }

    internal required byte[] Attestation { get; init; }

    internal required byte[] ClientDataJson { get; init; }
}
