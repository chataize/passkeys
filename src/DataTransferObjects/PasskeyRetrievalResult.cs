namespace ChatAIze.Passkeys.DataTransferObjects;

internal sealed record PasskeyRetrievalResult
{
    internal required byte[] CredentialId { get; init; }

    internal required byte[] AuthenticatorData { get; init; }

    internal required byte[] ClientDataJson { get; init; }

    internal required byte[] Signature { get; init; }
}

