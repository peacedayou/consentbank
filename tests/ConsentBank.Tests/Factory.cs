using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Time.Testing;

namespace ConsentBank.Tests;

public class Factory : WebApplicationFactory<Program>
{
    public const string Password = "Mot-de-passe-de-test-2026";
    public const string ClientSecret = "secret-client-de-test-0123456789";

    private readonly string _db = Path.Combine(Path.GetTempPath(), $"consentbank-{Guid.NewGuid()}.db");
    public FakeTimeProvider Clock { get; } = new(DateTimeOffset.UtcNow);

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting("ConnectionStrings:Default", $"Data Source={_db};Pooling=False");
        builder.UseSetting("Securite:ExigerHttps", "false");
        builder.UseSetting("Demo:MotDePasse", Password);
        builder.UseSetting("Demo:SecretClient", ClientSecret);
        builder.ConfigureTestServices(s =>
        {
            s.RemoveAll<TimeProvider>();
            s.AddSingleton<TimeProvider>(Clock);
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (File.Exists(_db))
        {
            File.Delete(_db);
        }
    }
}
