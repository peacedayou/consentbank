using System.Net;
using System.Security.Claims;
using ConsentBank.Data;
using ConsentBank.Services;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace ConsentBank.Endpoints;

/// <summary>Écrans de connexion et de consentement (HTML rendu côté serveur, protégés contre le CSRF).</summary>
public static class UiEndpoints
{
    public static void MapUi(this WebApplication app)
    {
        app.MapGet("/connexion", LoginPage);
        app.MapPost("/connexion", Login);
        app.MapPost("/deconnexion", async (HttpContext ctx, IAntiforgery af) =>
        {
            await af.ValidateRequestAsync(ctx);
            await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Results.Redirect("/");
        });
        app.MapGet("/consentement/{id:guid}", ConsentPage).RequireAuthorization();
        app.MapPost("/consentement/{id:guid}", Decide).RequireAuthorization();
    }

    private static IResult LoginPage(HttpContext ctx, IAntiforgery af, string? returnUrl, string? erreur) =>
        Html(ctx, "Connexion", $"""
            <h1>Connexion à ConsentBank</h1>
            {(erreur is null ? "" : "<p class=err>Courriel ou mot de passe invalide.</p>")}
            <form method="post" action="/connexion">
              {Token(ctx, af)}
              <input type="hidden" name="returnUrl" value="{E(returnUrl ?? "/portail")}">
              <label>Courriel <input name="courriel" type="email" autocomplete="username" required></label>
              <label>Mot de passe <input name="motDePasse" type="password" autocomplete="current-password" required></label>
              <button>Se connecter</button>
            </form>
            """);

    private static async Task<IResult> Login(HttpContext ctx, IAntiforgery af, BankDbContext db,
        IPasswordHasher<Customer> hasher, AuditLog audit)
    {
        if (!await Valid(ctx, af))
        {
            return Results.BadRequest();
        }
        var form = await ctx.Request.ReadFormAsync();
        var returnUrl = Local(form["returnUrl"]);
        var email = form["courriel"].ToString().Trim().ToLowerInvariant();
        var user = await db.Customers.FirstOrDefaultAsync(c => c.Email == email);
        if (user is null || hasher.VerifyHashedPassword(user, user.PasswordHash, form["motDePasse"].ToString()) == PasswordVerificationResult.Failed)
        {
            await audit.AppendAsync("connexion.echec", email, user?.Id, null, "");
            return Results.Redirect($"/connexion?erreur=1&returnUrl={Uri.EscapeDataString(returnUrl)}");
        }
        var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme, Claims.Name, Claims.Role);
        identity.AddClaim(new Claim(Claims.Subject, user.Id.ToString()));
        identity.AddClaim(new Claim(Claims.Name, user.Name));
        await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
        await audit.AppendAsync("connexion", "client", user.Id, null, "");
        return Results.Redirect(returnUrl);
    }

    private static async Task<IResult> ConsentPage(Guid id, HttpContext ctx, IAntiforgery af, BankDbContext db)
    {
        var pending = await Mine(id, ctx, db);
        if (pending is null || pending.Status != PendingStatus.Pending)
        {
            return Results.NotFound();
        }
        var accounts = await db.Accounts.Where(a => a.CustomerId == pending.CustomerId).ToListAsync();
        var scopes = string.Join("", pending.Scopes.Select(s => $"<li>{E(ConsentService.ScopeLabels[s])} <code>{E(s)}</code></li>"));
        var boxes = string.Join("", accounts.Select(a =>
            $"<label class=chk><input type=checkbox name=comptes value=\"{E(a.Id)}\"> {E(a.Name)} <small>({E(a.Id)})</small></label>"));
        var durations = string.Join("", ConsentService.Durations.Select(d => $"<option value={d}{(d == 90 ? " selected" : "")}>{d} jours</option>"));
        return Html(ctx, "Consentement", $"""
            <h1>{E(pending.ClientName)} demande l'accès à vos données</h1>
            <p>Cette application pourra :</p><ul>{scopes}</ul>
            <form method="post">
              {Token(ctx, af)}
              <fieldset><legend>Comptes partagés</legend>{boxes}</fieldset>
              <label>Durée <select name="duree">{durations}</select></label>
              <p class=note>Vous pourrez retirer ce consentement à tout moment dans votre portail.
              L'application ne peut ni faire de paiement ni modifier vos comptes.</p>
              <button name="decision" value="accepter">Autoriser</button>
              <button name="decision" value="refuser" class=sec>Refuser</button>
            </form>
            """);
    }

    private static async Task<IResult> Decide(Guid id, HttpContext ctx, IAntiforgery af, BankDbContext db, ConsentService consents)
    {
        if (!await Valid(ctx, af))
        {
            return Results.BadRequest();
        }
        var pending = await Mine(id, ctx, db);
        if (pending is null || pending.Status != PendingStatus.Pending)
        {
            return Results.NotFound();
        }
        var form = await ctx.Request.ReadFormAsync();
        if (form["decision"] == "accepter")
        {
            if (!int.TryParse(form["duree"], out var days) || !ConsentService.Durations.Contains(days))
            {
                return Results.BadRequest();
            }
            try
            {
                await consents.GrantAsync(pending, form["comptes"].Where(x => x is not null).Select(x => x!).ToList(), days);
            }
            catch (InvalidOperationException)
            {
                return Results.Redirect($"/consentement/{id}");
            }
        }
        else
        {
            pending.Status = PendingStatus.Denied;
            await db.SaveChangesAsync();
        }
        // Retour au point d'autorisation, qui émet le code (ou l'erreur access_denied).
        return Results.Redirect(pending.ReturnUrl.StartsWith("/connect/authorize?", StringComparison.Ordinal) ? pending.ReturnUrl : "/");
    }

    private static async Task<PendingConsent?> Mine(Guid id, HttpContext ctx, BankDbContext db)
    {
        var sub = ctx.User.FindFirst(Claims.Subject)?.Value;
        var p = await db.PendingConsents.FindAsync(id);
        return p is not null && sub is not null && p.CustomerId == Guid.Parse(sub) ? p : null;
    }

    private static async Task<bool> Valid(HttpContext ctx, IAntiforgery af)
    {
        try
        {
            await af.ValidateRequestAsync(ctx);
            return true;
        }
        catch (AntiforgeryValidationException)
        {
            return false;
        }
    }

    private static string Local(string? url) =>
        !string.IsNullOrEmpty(url) && url.StartsWith('/') && !url.StartsWith("//") && !url.StartsWith("/\\") ? url : "/portail";

    private static string Token(HttpContext ctx, IAntiforgery af)
    {
        var t = af.GetAndStoreTokens(ctx);
        return $"<input type=\"hidden\" name=\"{E(t.FormFieldName)}\" value=\"{E(t.RequestToken!)}\">";
    }

    internal static string E(string s) => WebUtility.HtmlEncode(s);

    private static IResult Html(HttpContext ctx, string title, string body)
    {
        ctx.Response.Headers.CacheControl = "no-store";
        ctx.Response.Headers["X-Frame-Options"] = "DENY";
        return Results.Content($$"""
            <!DOCTYPE html><html lang="fr-CA"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
            <title>{{E(title)}} – ConsentBank</title><link rel="stylesheet" href="/site.css"></head>
            <body><main class="narrow">{{body}}</main></body></html>
            """, "text/html; charset=utf-8");
    }
}
