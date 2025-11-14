using ChatAIze.Passkeys;
using ChatAIze.Passkeys.Preview.Components;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddPasskeyProvider(o =>
{
    o.Domain = "localhost";
    o.AppName = "Localhost";
    o.Origins = ["https://localhost:7238", "http://localhost:5192"];
});

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseAntiforgery();
app.UseStaticFiles();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();
app.Run();
