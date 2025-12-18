namespace ChatAIze.Passkeys.DataTransferObjects;

/// <summary>
/// Represents the raw assertion payload returned from the browser.
/// </summary>
/// <remarks>
/// This type is used for JS interop only and is not intended for external consumption.
/// </remarks>
internal sealed record PasskeyRetrievalResult
{
    /// <summary>
    /// Gets the user handle bytes.
    /// </summary>
    /// <remarks>
    /// This may be empty for non-discoverable credentials.
    /// </remarks>
    public required byte[] UserHandle { get; init; }

    /// <summary>
    /// Gets the credential identifier bytes.
    /// </summary>
    /// <remarks>
    /// Use this value to locate the stored public key during verification.
    /// </remarks>
    public required byte[] CredentialId { get; init; }

    /// <summary>
    /// Gets the authenticator data bytes.
    /// </summary>
    /// <remarks>
    /// Includes RP ID hash, flags, and signature counter.
    /// </remarks>
    public required byte[] AuthenticatorData { get; init; }

    /// <summary>
    /// Gets the client data JSON bytes.
    /// </summary>
    /// <remarks>
    /// Contains the challenge and origin as seen by the browser.
    /// </remarks>
    public required byte[] ClientDataJson { get; init; }

    /// <summary>
    /// Gets the signature bytes.
    /// </summary>
    /// <remarks>
    /// Used to verify the assertion using the stored public key.
    /// </remarks>
    public required byte[] Signature { get; init; }
}
