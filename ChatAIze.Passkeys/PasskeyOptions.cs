using System.Diagnostics.CodeAnalysis;

namespace ChatAIze.Passkeys;

/// <summary>
/// Defines configuration for passkey operations.
/// </summary>
/// <remarks>
/// <para>
/// The <see cref="Domain"/> value is the relying party identifier (rpId) and must be an effective
/// domain (no scheme or path). Origins must match the exact scheme/host/port of the app.
/// </para>
/// <para>
/// For Blazor Server, ensure the origin includes the public URL you expect users to access
/// (for example, <c>https://example.com</c> or a localhost URL during development).
/// </para>
/// </remarks>
public sealed record PasskeyOptions
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PasskeyOptions"/> class.
    /// </summary>
    public PasskeyOptions() { }

    /// <summary>
    /// Initializes a new instance of the <see cref="PasskeyOptions"/> class with required values.
    /// </summary>
    /// <param name="appName">The relying party display name.</param>
    /// <param name="domain">The relying party identifier.</param>
    /// <param name="origins">The allowed origins for client data validation.</param>
    [SetsRequiredMembers]
    public PasskeyOptions(string appName, string domain, List<string> origins)
    {
        AppName = appName;
        Domain = domain;
        Origins = origins;
    }

    /// <summary>
    /// Gets or sets the relying party display name.
    /// </summary>
    /// <remarks>
    /// This is shown to users by authenticators during registration and authentication.
    /// </remarks>
    public required string AppName { get; set; }

    /// <summary>
    /// Gets or sets the relying party identifier (rpId).
    /// </summary>
    /// <remarks>
    /// Use a registrable domain such as <c>example.com</c>. Do not include scheme or path.
    /// The rpId must match the effective domain of the origin.
    /// </remarks>
    public required string Domain { get; set; }

    /// <summary>
    /// Gets or sets the list of allowed origins.
    /// </summary>
    /// <remarks>
    /// Provide the exact origin(s) (scheme + host + port) that will call the WebAuthn APIs.
    /// If these do not match, verification will fail.
    /// </remarks>
    public required List<string> Origins { get; set; }
}
