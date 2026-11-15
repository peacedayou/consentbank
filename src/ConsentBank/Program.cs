using ConsentBank.Components;
using ConsentBank.Data;
using ConsentBank.Endpoints;
using ConsentBank.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddDbContext<BankDbContext>(o =>
{
    o.UseSqlite(config.GetConnectionString("Default") ?? "Data Source=consentbank.db");
    o.UseOpenIddict();
});
builder.Services.AddScoped<AuditLog>();
builder.Services.AddScoped<ConsentService>();
builder.Services.AddScoped<IPasswordHasher<Customer>, PasswordHasher<Customer>>();

// Le transport HTTPS est exigé par défaut ; on ne le désactive que pour les tests et la démo locale.
var requireHttps = config.GetValue("Securite:ExigerHttps", true);

builder.Services.AddOpenIddict()
    .AddCore(o => o.UseEntityFrameworkCore().UseDbContext<BankDbContext>())
    .AddServer(o =>
    {
        o.SetAuthorizationEndpointUris("connect/authorize")
         .SetPushedAuthorizationEndpointUris("connect/par")
         .SetTokenEndpointUris("connect/token");

        // Profil inspiré de FAPI 2.0 : code d'autorisation seulement, PKCE (S256) et PAR obligatoires.
        o.AllowAuthorizationCodeFlow();
        o.RequireProofKeyForCodeExchange();
        o.RequirePushedAuthorizationRequests();
        o.RegisterScopes(ConsentService.Scopes.AccountsRead, ConsentService.Scopes.TransactionsRead);

        o.SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(1));
        o.SetAccessTokenLifetime(TimeSpan.FromMinutes(10));

        // Clés éphémères : renouvelées à chaque démarrage (démonstration). En production : certificats gérés.
        o.AddEphemeralEncryptionKey().AddEphemeralSigningKey();
        o.DisableAccessTokenEncryption();

        var aspnet = o.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableTokenEndpointPassthrough();
        if (!requireHttps)
        {
            aspnet.DisableTransportSecurityRequirement();
        }
    })
    .AddValidation(o =>
    {
        o.UseLocalServer();
        o.UseAspNetCore();
        // Chaque appel vérifie que l'autorisation n'a pas été révoquée entre-temps.
        o.EnableAuthorizationEntryValidation();
        o.EnableTokenEntryValidation();
    });

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o =>
    {
        o.LoginPath = "/connexion";
        o.Cookie.Name = "consentbank";
        o.Cookie.HttpOnly = true;
        o.Cookie.SameSite = SameSiteMode.Lax;
        o.Cookie.SecurePolicy = requireHttps ? CookieSecurePolicy.Always : CookieSecurePolicy.SameAsRequest;
        o.ExpireTimeSpan = TimeSpan.FromMinutes(20);
        o.SlidingExpiration = true;
    });
builder.Services.AddAuthorization(o => o.AddPolicy(BankApi.Policy, p =>
{
    p.AuthenticationSchemes.Add(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
    p.RequireAuthenticatedUser();
}));
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddRazorComponents();
builder.Services.AddAntiforgery(o => o.Cookie.Name = "consentbank.af");
builder.Services.AddProblemDetails();
builder.Services.AddHealthChecks();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    await Seed.RunAsync(scope.ServiceProvider, config);
}

if (requireHttps)
{
    app.UseHsts();
    app.UseHttpsRedirection();
}
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapOAuth();
app.MapBankApi();
app.MapUi();
app.MapHealthChecks("/sante");
app.MapRazorComponents<App>();

app.Run();

public partial class Program;
