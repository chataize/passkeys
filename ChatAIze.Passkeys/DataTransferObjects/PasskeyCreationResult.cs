namespace ChatAIze.Passkeys.DataTransferObjects;

/// <summary>
/// Represents the raw attestation payload returned from the browser.
/// </summary>
/// <remarks>
/// This type is used for JS interop only and is not intended for external consumption.
/// </remarks>
internal sealed record PasskeyCreationResult
{
    /// <summary>
    /// Gets the credential identifier bytes.
    /// </summary>
    /// <remarks>
    /// This is the raw ID returned by WebAuthn during registration.
    /// </remarks>
    public required byte[] CredentialId { get; init; }

    /// <summary>
    /// Gets the attestation object bytes.
    /// </summary>
    /// <remarks>
    /// This contains authenticator data and attestation statement.
    /// </remarks>
    public required byte[] Attestation { get; init; }

    /// <summary>
    /// Gets the client data JSON bytes.
    /// </summary>
    /// <remarks>
    /// This contains the challenge and origin as seen by the browser.
    /// </remarks>
    public required byte[] ClientDataJson { get; init; }
}
