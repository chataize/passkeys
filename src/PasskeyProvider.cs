using Microsoft.Extensions.DependencyInjection;
using Microsoft.JSInterop;

namespace ChatAIze.Passkeys;

public sealed class PasskeyProvider(IJSRuntime jsRuntime) : IAsyncDisposable
{
    private readonly Lazy<Task<IJSObjectReference>> moduleTask = new(() => jsRuntime.InvokeAsync<IJSObjectReference>("import", "./_content/Passkeys/passkeys.js").AsTask());

    public async ValueTask CreatePasskeyAsync()
    {
        var module = await moduleTask.Value;
        await module.InvokeVoidAsync("createPasskey");
    }

    public async ValueTask ValueTaskGetPasskeyAsync()
    {
        var module = await moduleTask.Value;
        await module.InvokeAsync<string>("getPasskey");
    }

    public async ValueTask DisposeAsync()
    {
        if (moduleTask.IsValueCreated)
        {
            var module = await moduleTask.Value;
            await module.DisposeAsync();
        }
    }
}

public static class PasskeyProviderExtensions
{
    public static IServiceCollection AddPasskeyProvider(this IServiceCollection services)
    {
        return services.AddScoped<PasskeyProvider>();
    }
}
