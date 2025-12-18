using Microsoft.Extensions.DependencyInjection;

namespace ChatAIze.Passkeys;

/// <summary>
/// Provides DI registration helpers for passkey services.
/// </summary>
/// <remarks>
/// Register this in <c>Program.cs</c> so the provider can be injected into Blazor components.
/// </remarks>
public static class PasskeyProviderExtensions
{
    /// <summary>
    /// Registers <see cref="PasskeyProvider"/> and configures <see cref="PasskeyOptions"/>.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">The configuration action.</param>
    /// <returns>The updated service collection.</returns>
    /// <example>
    /// <code>
    /// builder.Services.AddPasskeyProvider(options =>
    /// {
    ///     options.Domain = "example.com";
    ///     options.AppName = "Example";
    ///     options.Origins = new List&lt;string&gt; { "https://example.com" };
    /// });
    /// </code>
    /// </example>
    public static IServiceCollection AddPasskeyProvider(this IServiceCollection services, Action<PasskeyOptions> configure)
    {
        services.AddScoped<PasskeyProvider>();
        services.Configure(configure);

        return services;
    }
}
