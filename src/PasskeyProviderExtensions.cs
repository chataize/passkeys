using Microsoft.Extensions.DependencyInjection;

namespace ChatAIze.Passkeys;

public static class PasskeyProviderExtensions
{
    public static IServiceCollection AddPasskeyProvider(this IServiceCollection services, Action<PasskeyOptions> configure)
    {
        services.AddScoped<PasskeyProvider>();
        services.Configure(configure);

        return services;
    }
}
