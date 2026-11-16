using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using ConsentBank.Data;
using ConsentBank.Services;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace ConsentBank.Tests;

/// <summary>
/// Parcours complet, comme le ferait une application tierce et son utilisateur :
/// PAR → autorisation → connexion → consentement → code → jeton (PKCE) → API → révocation.
/// </summary>
public partial class ConsentFlowTests : IDisposable
{
    private const string Scopes = "comptes:lecture transactions:lecture";
    private readonly Factory _factory = new();
    private readonly HttpClient _browser;   // navigateur de l'utilisateur (cookies, pas de redirection automatique)
    private readonly HttpClient _app;       // serveur de l'application tierce

    public ConsentFlowTests()
    {
        _browser = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true });
        _app = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });
    }

    public void Dispose() => _factory.Dispose();

    [GeneratedRegex("name=\"__RequestVerificationToken\" value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryRegex();

    private static (string Verifier, string Challenge) Pkce()
    {
        var verifier = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var challenge = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return (verifier, challenge);
    }

    private async Task<HttpResponseMessage> Par(string challenge, string scope = Scopes, string? secret = Factory.ClientSecret) =>
        await _app.PostAsync("/connect/par", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = Seed.ClientId,
            ["client_secret"] = secret ?? "",
            ["response_type"] = "code",
            ["redirect_uri"] = Seed.RedirectUri,
            ["scope"] = scope,
            ["state"] = "etat-123",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
        }));

    private async Task<string> Token(HttpResponseMessage page)
    {
        var html = await page.Content.ReadAsStringAsync();
        return WebUtility.HtmlDecode(AntiforgeryRegex().Match(html).Groups[1].Value);
    }

    private async Task<HttpResponseMessage> PostForm(string url, string token, params (string, string)[] fields)
    {
        var list = fields.Select(f => new KeyValuePair<string, string>(f.Item1, f.Item2)).ToList();
        list.Add(new("__RequestVerificationToken", token));
        return await _browser.PostAsync(url, new FormUrlEncodedContent(list));
    }

    /// <summary>Déroule le parcours jusqu'au code. Renvoie (code, vérificateur PKCE, id du consentement en attente).</summary>
    private async Task<(string Code, string Verifier)> ObtainCode(string[] accounts, string decision = "accepter", int days = 90)
    {
        var (verifier, challenge) = Pkce();
        var par = await Par(challenge);
        Assert.True(par.IsSuccessStatusCode, $"PAR : {par.StatusCode} {await par.Content.ReadAsStringAsync()}");
        var requestUri = (await par.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("request_uri").GetString()!;

        var authorizeUrl = $"/connect/authorize?client_id={Seed.ClientId}&request_uri={Uri.EscapeDataString(requestUri)}";
        var r = await _browser.GetAsync(authorizeUrl);
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.StartsWith("/connexion", r.Headers.Location!.PathAndQuery);

        var loginPage = await _browser.GetAsync(r.Headers.Location);
        r = await PostForm("/connexion", await Token(loginPage),
            ("courriel", "alice@exemple.ca"), ("motDePasse", Factory.Password), ("returnUrl", authorizeUrl));
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);

        r = await _browser.GetAsync(r.Headers.Location);
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        var consentUrl = r.Headers.Location!.OriginalString;
        Assert.StartsWith("/consentement/", consentUrl);

        var consentPage = await _browser.GetAsync(consentUrl);
        var html = WebUtility.HtmlDecode(await consentPage.Content.ReadAsStringAsync());
        Assert.Contains("Budget Futé", html);
        var fields = new List<(string, string)> { ("decision", decision), ("duree", days.ToString()) };
        fields.AddRange(accounts.Select(a => ("comptes", a)));
        r = await PostForm(consentUrl, await Token(consentPage), fields.ToArray());
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);

        r = await _browser.GetAsync(r.Headers.Location);   // retour au point d'autorisation
        Assert.True(r.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found, $"statut {r.StatusCode}");
        var callback = r.Headers.Location!;
        Assert.StartsWith(Seed.RedirectUri, callback.ToString());
        var query = System.Web.HttpUtility.ParseQueryString(callback.Query);
        Assert.Equal("etat-123", query["state"]);
        return (query["code"] ?? "ERREUR:" + query["error"], verifier);
    }

    private async Task<HttpResponseMessage> Exchange(string code, string verifier) =>
        await _app.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = Seed.ClientId,
            ["client_secret"] = Factory.ClientSecret,
            ["code"] = code,
            ["redirect_uri"] = Seed.RedirectUri,
            ["code_verifier"] = verifier,
        }));

    private async Task<string> AccessToken(params string[] accounts)
    {
        var (code, verifier) = await ObtainCode(accounts);
        var r = await Exchange(code, verifier);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("access_token").GetString()!;
    }

    private async Task<HttpResponseMessage> Api(string path, string token)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, path);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await _app.SendAsync(req);
    }

    [Fact]
    public async Task ParcoursComplet_seulsLesComptesChoisisSontVisibles()
    {
        var token = await AccessToken("CHQ-001");
        var r = await Api("/api/v1/comptes", token);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var comptes = await r.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(1, comptes.GetArrayLength());
        Assert.Equal("CHQ-001", comptes[0].GetProperty("id").GetString());

        var ops = await (await Api("/api/v1/comptes/CHQ-001/operations", token)).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(3, ops.GetArrayLength());   // l'opération de plus de 90 jours est exclue

        Assert.Equal(HttpStatusCode.Forbidden, (await Api("/api/v1/comptes/EPA-002/operations", token)).StatusCode);
    }

    [Fact]
    public async Task Revocation_coupeLAccesImmediatement()
    {
        var token = await AccessToken("CHQ-001", "EPA-002");
        Assert.Equal(HttpStatusCode.OK, (await Api("/api/v1/comptes", token)).StatusCode);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<BankDbContext>();
            var consent = await db.Consents.SingleAsync();
            Assert.True(await scope.ServiceProvider.GetRequiredService<ConsentService>().RevokeAsync(consent.Id, consent.CustomerId));
        }

        var after = await Api("/api/v1/comptes", token);
        Assert.True(after.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden, $"statut {after.StatusCode}");
    }

    [Fact]
    public async Task Expiration_duConsentement()
    {
        var token = await AccessToken("CHQ-001");
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<BankDbContext>();
            var c = await db.Consents.SingleAsync();
            c.ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1);   // consentement arrivé à échéance
            await db.SaveChangesAsync();
        }
        Assert.Equal(HttpStatusCode.Forbidden, (await Api("/api/v1/comptes", token)).StatusCode);
    }

    [Fact]
    public async Task Pkce_mauvaisVerificateurRefuse()
    {
        var (code, _) = await ObtainCode(["CHQ-001"]);
        var r = await Exchange(code, Pkce().Verifier);
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.Contains("invalid_grant", await r.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Code_utilisableUneSeuleFois()
    {
        var (code, verifier) = await ObtainCode(["CHQ-001"]);
        Assert.Equal(HttpStatusCode.OK, (await Exchange(code, verifier)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Exchange(code, verifier)).StatusCode);
    }

    [Fact]
    public async Task Refus_renvoieAccessDenied()
    {
        var (code, _) = await ObtainCode(["CHQ-001"], decision: "refuser");
        Assert.Equal("ERREUR:access_denied", code);
    }

    [Fact]
    public async Task AutorisationSansPar_refusee()
    {
        var (_, challenge) = Pkce();
        var r = await _browser.GetAsync($"/connect/authorize?client_id={Seed.ClientId}&response_type=code&redirect_uri="
            + Uri.EscapeDataString(Seed.RedirectUri) + $"&scope=comptes:lecture&code_challenge={challenge}&code_challenge_method=S256");
        Assert.True(r.StatusCode is HttpStatusCode.BadRequest || (r.Headers.Location?.ToString().Contains("error=") ?? false),
            $"statut {r.StatusCode}");
    }

    [Fact]
    public async Task ParSansPkce_ouMauvaisSecret_refuse()
    {
        var sansPkce = await _app.PostAsync("/connect/par", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = Seed.ClientId, ["client_secret"] = Factory.ClientSecret, ["response_type"] = "code",
            ["redirect_uri"] = Seed.RedirectUri, ["scope"] = Scopes,
        }));
        Assert.Equal(HttpStatusCode.BadRequest, sansPkce.StatusCode);
        Assert.False((await Par(Pkce().Challenge, secret: "mauvais")).IsSuccessStatusCode);
    }

    [Fact]
    public async Task ApiSansJeton_401()
    {
        var r = await _app.GetAsync("/api/v1/comptes");
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
    }

    [Fact]
    public async Task JournalAudit_chaineIntegreEtAlterationDetectee()
    {
        await AccessToken("CHQ-001");
        using var scope = _factory.Services.CreateScope();
        var audit = scope.ServiceProvider.GetRequiredService<AuditLog>();
        var db = scope.ServiceProvider.GetRequiredService<BankDbContext>();
        var types = await db.Audit.Select(a => a.Type).ToListAsync();
        Assert.Contains("consentement.accorde", types);
        Assert.Contains("jeton.emis", types);
        Assert.Null(await audit.VerifyAsync());

        var entry = await db.Audit.OrderBy(a => a.Id).Skip(1).FirstAsync();
        entry.Detail = "modifié après coup";
        await db.SaveChangesAsync();
        Assert.Equal(entry.Id, await audit.VerifyAsync());
    }

    [Fact]
    public async Task Portail_listeEtRevocation()
    {
        await AccessToken("CHQ-001");
        var page = await _browser.GetAsync("/portail");
        var html = WebUtility.HtmlDecode(await page.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Contains("Budget Futé", html);
        Assert.Contains("Retirer l'accès", html);
    }
}
