using System.Security.Cryptography;
using System.Text;
using ConsentBank.Data;
using Microsoft.EntityFrameworkCore;

namespace ConsentBank.Services;

/// <summary>
/// Journal d'audit en ajout seulement, chaîné par SHA-256 : modifier ou supprimer une entrée
/// casse la chaîne, et <see cref="VerifyAsync"/> le détecte.
/// </summary>
public class AuditLog(BankDbContext db, TimeProvider clock)
{
    private static readonly SemaphoreSlim Gate = new(1, 1);

    public async Task<AuditEntry> AppendAsync(string type, string actor, Guid? customerId, Guid? consentId, string detail)
    {
        await Gate.WaitAsync();
        try
        {
            var last = await db.Audit.OrderByDescending(a => a.Id).Select(a => a.Hash).FirstOrDefaultAsync() ?? "";
            var entry = new AuditEntry
            {
                At = clock.GetUtcNow(), Type = type, Actor = actor, CustomerId = customerId, ConsentId = consentId,
                Detail = detail, PreviousHash = last,
            };
            entry.Hash = Compute(entry);
            db.Audit.Add(entry);
            await db.SaveChangesAsync();
            return entry;
        }
        finally
        {
            Gate.Release();
        }
    }

    /// <summary>Renvoie l'identifiant de la première entrée altérée, ou null si la chaîne est intacte.</summary>
    public async Task<long?> VerifyAsync()
    {
        var previous = "";
        await foreach (var e in db.Audit.AsNoTracking().OrderBy(a => a.Id).AsAsyncEnumerable())
        {
            if (e.PreviousHash != previous || e.Hash != Compute(e))
            {
                return e.Id;
            }
            previous = e.Hash;
        }
        return null;
    }

    public static string Compute(AuditEntry e)
    {
        var data = string.Join('|', e.PreviousHash, e.At.ToUniversalTime().ToString("O"), e.Type, e.Actor,
            e.CustomerId?.ToString() ?? "", e.ConsentId?.ToString() ?? "", e.Detail);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(data)));
    }
}
