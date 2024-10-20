using Microsoft.JSInterop;

namespace ChatAIze.Passkeys;

public sealed class PasskeyProvider(IJSRuntime jsRuntime) : IAsyncDisposable
{
    private readonly Lazy<Task<IJSObjectReference>> moduleTask = new(() => jsRuntime.InvokeAsync<IJSObjectReference>("import", "./_content/ChatAIze.Passkeys/passkeys.js").AsTask());

    public async ValueTask CreatePasskeyAsync()
    {
        var module = await moduleTask.Value;
        await module.InvokeVoidAsync("createPasskey");
    }

    public async ValueTask GetPasskeyAsync()
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
