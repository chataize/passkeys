namespace ChatAIze.Passkeys;

/// <summary>
/// Represents a registered or asserted passkey along with verification data.
/// </summary>
/// <remarks>
/// <para>
/// This model combines registration data (credential ID/public key) and assertion data
/// (authenticator response fields). The internal assertion fields are transient and intended
/// for immediate verification, not long-term storage.
/// </para>
/// <para>
/// For non-discoverable credentials, the browser may return an empty user handle; treat an empty
/// handle as "unknown user" and resolve the user by credential ID instead.
/// </para>
/// </remarks>
public sealed record Passkey
{
    /// <summary>
    /// Gets the user handle associated with the credential.
    /// </summary>
    /// <remarks>
    /// The handle is an application-defined stable identifier. It can be empty for some assertions
    /// (for example, non-discoverable security keys).
    /// </remarks>
    public required byte[] UserHandle { get; init; }

    /// <summary>
    /// Gets the credential identifier.
    /// </summary>
    /// <remarks>
    /// Persist this value and use it to look up credentials during authentication.
    /// </remarks>
    public required byte[] CredentialId { get; init; }

    /// <summary>
    /// Gets the credential public key when available.
    /// </summary>
    /// <remarks>
    /// Store the public key for later verification. It is populated after successful registration.
    /// </remarks>
    public byte[]? PublicKey { get; init; }

    /// <summary>
    /// Gets the user handle encoded as base64.
    /// </summary>
    /// <remarks>
    /// This uses standard base64 (not base64url). Convert to base64url if required by your storage or API.
    /// </remarks>
    public string UserHandleBase64 => Convert.ToBase64String(UserHandle);

    /// <summary>
    /// Gets the credential identifier encoded as base64.
    /// </summary>
    /// <remarks>
    /// This uses standard base64 (not base64url). Convert to base64url if required by your storage or API.
    /// </remarks>
    public string CredentialIdBase64 => Convert.ToBase64String(CredentialId);

    /// <summary>
    /// Gets the public key encoded as base64 when available.
    /// </summary>
    /// <remarks>
    /// This uses standard base64 (not base64url). Convert to base64url if required by your storage or API.
    /// </remarks>
    public string? PublicKeyBase64 => PublicKey is not null ? Convert.ToBase64String(PublicKey) : null;

    /// <summary>
    /// Gets the challenge used for assertion verification.
    /// </summary>
    internal byte[]? Challenge { get; init; }

    /// <summary>
    /// Gets the authenticator data from the assertion response.
    /// </summary>
    internal byte[]? AuthenticatorData { get; init; }

    /// <summary>
    /// Gets the client data JSON from the assertion response.
    /// </summary>
    internal byte[]? ClientDataJson { get; init; }

    /// <summary>
    /// Gets the signature from the assertion response.
    /// </summary>
    internal byte[]? Signature { get; init; }
}
