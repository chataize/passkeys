namespace ChatAIze.Passkeys.DataTransferObjects;

internal sealed record PasskeyRetrievalResult
{
    public required byte[] CredentialId { get; init; }

    public required byte[] AuthenticatorData { get; init; }

    public required byte[] ClientDataJson { get; init; }

    public required byte[] Signature { get; init; }
}

