using ConsentBank.Data;
using ConsentBank.Services;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

namespace ConsentBank.Endpoints;

/// <summary>
/// API de données bancaires pour les applications tierces. Chaque appel vérifie le jeton (OpenIddict),
/// la portée demandée et le consentement en base : seuls les comptes choisis par le client sont visibles,
/// et un consentement révoqué ou expiré coupe l'accès immédiatement.
/// </summary>
public static class BankApi
{
    public const string Policy = "api-bancaire";

    public static void MapBankApi(this WebApplication app)
    {
        var api = app.MapGroup("/api/v1").RequireAuthorization(Policy);
        api.MapGet("/comptes", Accounts);
        api.MapGet("/comptes/{id}/operations", Transactions);
    }

    private record AccountDto(string Id, string Nom, decimal Solde, string Devise);
    private record TransactionDto(DateOnly Date, string Description, decimal Montant);

    private static async Task<IResult> Accounts(HttpContext ctx, BankDbContext db, ConsentService consents, AuditLog audit)
    {
        var (consent, error) = await Check(ctx, consents, ConsentService.Scopes.AccountsRead);
        if (consent is null)
        {
            return error!;
        }
        var list = await db.Accounts.Where(a => consent.AccountIds.Contains(a.Id))
            .Select(a => new AccountDto(a.Id, a.Name, a.Balance, a.Currency)).ToListAsync();
        await audit.AppendAsync("donnees.consultees", consent.ClientId, consent.CustomerId, consent.Id, "comptes");
        return Results.Ok(list);
    }

    private static async Task<IResult> Transactions(string id, HttpContext ctx, BankDbContext db, ConsentService consents,
        AuditLog audit, TimeProvider clock)
    {
        var (consent, error) = await Check(ctx, consents, ConsentService.Scopes.TransactionsRead);
        if (consent is null)
        {
            return error!;
        }
        if (!consent.AccountIds.Contains(id))
        {
            return Results.Problem(statusCode: 403, title: "Compte non couvert par le consentement");
        }
        var since = DateOnly.FromDateTime(clock.GetUtcNow().UtcDateTime.AddDays(-90));
        var list = (await db.Transactions.Where(t => t.AccountId == id).ToListAsync())
            .Where(t => t.Date >= since).OrderByDescending(t => t.Date)
            .Select(t => new TransactionDto(t.Date, t.Description, t.Amount)).ToList();
        await audit.AppendAsync("donnees.consultees", consent.ClientId, consent.CustomerId, consent.Id, $"operations {id}");
        return Results.Ok(list);
    }

    private static async Task<(Consent?, IResult?)> Check(HttpContext ctx, ConsentService consents, string scope)
    {
        if (!ctx.User.HasScope(scope))
        {
            return (null, Results.Problem(statusCode: 403, title: "Portée insuffisante", detail: $"Portée requise : {scope}"));
        }
        if (ctx.User.GetClaim(OAuthEndpoints.ConsentClaim) is not { } id
            || await consents.FindActiveAsync(Guid.Parse(id)) is not { } consent)
        {
            return (null, Results.Problem(statusCode: 403, title: "Consentement révoqué ou expiré"));
        }
        return (consent, null);
    }
}
