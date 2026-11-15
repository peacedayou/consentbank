using System.Collections.Immutable;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using ConsentBank.Data;
using ConsentBank.Services;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace ConsentBank.Endpoints;

/// <summary>
/// Point d'autorisation (après la requête poussée PAR) et point de jeton.
/// Le client s'authentifie (cookie), puis décide sur l'écran de consentement ; le code n'est émis
/// qu'après une décision explicite, et seulement pour les portées accordées.
/// </summary>
public static class OAuthEndpoints
{
    public const string ConsentClaim = "consent_id";

    public static void MapOAuth(this WebApplication app)
    {
        app.MapMethods("/connect/authorize", ["GET", "POST"], Authorize);
        app.MapPost("/connect/token", Token);
    }

    private static async Task<IResult> Authorize(
        HttpContext ctx,
        BankDbContext db,
        AuditLog audit,
        TimeProvider clock,
        IOpenIddictApplicationManager applications,
        IOpenIddictAuthorizationManager authorizations)
    {
        var request = ctx.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("Requête OpenID Connect introuvable.");

        var cookie = await ctx.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        var returnUrl = ctx.Request.PathBase + ctx.Request.Path + ctx.Request.QueryString;
        if (!cookie.Succeeded || cookie.Principal.FindFirst(Claims.Subject)?.Value is not { } sub)
        {
            return Results.Challenge(new AuthenticationProperties { RedirectUri = returnUrl },
                [CookieAuthenticationDefaults.AuthenticationScheme]);
        }
        var customerId = Guid.Parse(sub);

        var application = await applications.FindByClientIdAsync(request.ClientId!)
            ?? throw new InvalidOperationException("Application inconnue.");
        var clientName = await applications.GetDisplayNameAsync(application) ?? request.ClientId!;

        // Une même URL d'autorisation (même request_uri) correspond à une seule demande de consentement.
        var key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sub + "|" + ctx.Request.QueryString.Value)));
        var pending = await db.PendingConsents.FirstOrDefaultAsync(p => p.RequestKey == key);

        if (pending is null)
        {
            var requested = request.GetScopes().Where(ConsentService.ScopeLabels.ContainsKey).ToList();
            pending = new PendingConsent
            {
                RequestKey = key, CustomerId = customerId, ClientId = request.ClientId!, ClientName = clientName,
                Scopes = requested, ReturnUrl = returnUrl, CreatedAt = clock.GetUtcNow(),
            };
            db.PendingConsents.Add(pending);
            await db.SaveChangesAsync();
            return Results.Redirect($"/consentement/{pending.Id}");
        }

        if (pending.Status == PendingStatus.Denied)
        {
            await audit.AppendAsync("consentement.refuse", "client", customerId, null, clientName);
            return Forbid(Errors.AccessDenied, "Le client a refusé le partage de ses données.");
        }
        if (pending.Status != PendingStatus.Approved || pending.ConsentId is null)
        {
            return pending.Status == PendingStatus.Used
                ? Forbid(Errors.InvalidRequest, "Cette demande d'autorisation a déjà été utilisée.")
                : Results.Redirect($"/consentement/{pending.Id}");
        }

        var consent = await db.Consents.FindAsync(pending.ConsentId.Value)
            ?? throw new InvalidOperationException("Consentement introuvable.");

        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);
        identity.SetClaim(Claims.Subject, sub)
                .SetClaim(ConsentClaim, consent.Id.ToString());
        identity.SetScopes(request.GetScopes().Intersect(consent.Scopes));
        identity.SetDestinations(_ => [Destinations.AccessToken]);

        var authorization = await authorizations.CreateAsync(
            identity: identity,
            subject: sub,
            client: (await applications.GetIdAsync(application))!,
            type: AuthorizationTypes.Permanent,
            scopes: identity.GetScopes());
        var authorizationId = await authorizations.GetIdAsync(authorization);
        identity.SetAuthorizationId(authorizationId);

        consent.AuthorizationId = authorizationId;
        pending.Status = PendingStatus.Used;
        await db.SaveChangesAsync();
        await audit.AppendAsync("code.emis", "serveur", customerId, consent.Id, clientName);

        return Results.SignIn(new ClaimsPrincipal(identity), properties: null,
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static async Task<IResult> Token(HttpContext ctx, ConsentService consents, AuditLog audit)
    {
        var request = ctx.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("Requête OpenID Connect introuvable.");
        if (!request.IsAuthorizationCodeGrantType())
        {
            return Forbid(Errors.UnsupportedGrantType, "Seul le flux par code d'autorisation est accepté.");
        }

        var result = await ctx.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var principal = result.Principal;
        if (principal?.GetClaim(ConsentClaim) is not { } consentId
            || await consents.FindActiveAsync(Guid.Parse(consentId)) is not { } consent)
        {
            return Forbid(Errors.InvalidGrant, "Le consentement a été révoqué ou a expiré.");
        }
        await audit.AppendAsync("jeton.emis", "serveur", consent.CustomerId, consent.Id, consent.ClientName);
        return Results.SignIn(principal, properties: null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static IResult Forbid(string error, string description) =>
        Results.Forbid(
            new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
            }),
            [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
}
