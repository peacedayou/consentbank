using ConsentBank.Data;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

namespace ConsentBank.Services;

public class ConsentService(
    BankDbContext db,
    AuditLog audit,
    TimeProvider clock,
    IOpenIddictAuthorizationManager authorizations,
    IOpenIddictTokenManager tokens)
{
    /// <summary>Durées proposées au client sur l'écran de consentement (en jours).</summary>
    public static readonly int[] Durations = [30, 90, 365];

    public static readonly Dictionary<string, string> ScopeLabels = new()
    {
        [Scopes.AccountsRead] = "Voir la liste et le solde des comptes choisis",
        [Scopes.TransactionsRead] = "Voir les opérations des comptes choisis (90 derniers jours)",
    };

    public static class Scopes
    {
        public const string AccountsRead = "comptes:lecture";
        public const string TransactionsRead = "transactions:lecture";
    }

    public async Task<Consent> GrantAsync(PendingConsent pending, IReadOnlyCollection<string> accountIds, int days)
    {
        if (!Durations.Contains(days))
        {
            throw new ArgumentOutOfRangeException(nameof(days));
        }
        var owned = await db.Accounts.Where(a => a.CustomerId == pending.CustomerId).Select(a => a.Id).ToListAsync();
        var chosen = accountIds.Where(owned.Contains).Distinct().ToList();
        if (chosen.Count == 0)
        {
            throw new InvalidOperationException("Choisissez au moins un de vos comptes.");
        }
        var now = clock.GetUtcNow();
        var consent = new Consent
        {
            CustomerId = pending.CustomerId, ClientId = pending.ClientId, ClientName = pending.ClientName,
            Scopes = pending.Scopes.ToList(), AccountIds = chosen, GrantedAt = now, ExpiresAt = now.AddDays(days),
        };
        db.Consents.Add(consent);
        pending.Status = PendingStatus.Approved;
        pending.ConsentId = consent.Id;
        await db.SaveChangesAsync();
        await audit.AppendAsync("consentement.accorde", "client", consent.CustomerId, consent.Id,
            $"{consent.ClientName} ; portée : {string.Join(' ', consent.Scopes)} ; comptes : {string.Join(',', chosen)} ; {days} jours");
        return consent;
    }

    public async Task<Consent?> FindActiveAsync(Guid consentId)
    {
        var c = await db.Consents.FindAsync(consentId);
        return c is not null && c.IsActiveAt(clock.GetUtcNow()) ? c : null;
    }

    // Tri en mémoire : SQLite ne sait pas trier sur DateTimeOffset.
    public async Task<List<Consent>> ListAsync(Guid customerId) =>
        (await db.Consents.Where(c => c.CustomerId == customerId).ToListAsync()).OrderByDescending(c => c.GrantedAt).ToList();

    /// <summary>
    /// Révocation immédiate : le consentement passe à « révoqué », l'autorisation OpenIddict et tous
    /// ses jetons sont révoqués. Un jeton d'accès déjà émis est refusé dès l'appel suivant.
    /// </summary>
    public async Task<bool> RevokeAsync(Guid consentId, Guid customerId)
    {
        var c = await db.Consents.FirstOrDefaultAsync(x => x.Id == consentId && x.CustomerId == customerId);
        if (c is null || c.Status == ConsentStatus.Revoked)
        {
            return false;
        }
        c.Status = ConsentStatus.Revoked;
        c.RevokedAt = clock.GetUtcNow();
        await db.SaveChangesAsync();
        if (c.AuthorizationId is not null)
        {
            var authorization = await authorizations.FindByIdAsync(c.AuthorizationId);
            if (authorization is not null)
            {
                await authorizations.TryRevokeAsync(authorization);
            }
            await tokens.RevokeByAuthorizationIdAsync(c.AuthorizationId);
        }
        await audit.AppendAsync("consentement.revoque", "client", c.CustomerId, c.Id, c.ClientName);
        return true;
    }
}
