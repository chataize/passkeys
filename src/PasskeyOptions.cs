using System.Diagnostics.CodeAnalysis;

namespace ChatAIze.Passkeys;

public sealed record PasskeyOptions
{
    public PasskeyOptions() { }

    [SetsRequiredMembers]
    public PasskeyOptions(string appName, string domain, List<string> origins)
    {
        AppName = appName;
        Domain = domain;
        Origins = origins;
    }

    public required string AppName { get; set; }

    public required string Domain { get; set; }

    public required List<string> Origins { get; set; }
}
