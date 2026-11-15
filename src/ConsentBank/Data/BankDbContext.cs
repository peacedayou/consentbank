using Microsoft.EntityFrameworkCore;

namespace ConsentBank.Data;

public class BankDbContext(DbContextOptions<BankDbContext> options) : DbContext(options)
{
    public DbSet<Customer> Customers => Set<Customer>();
    public DbSet<Account> Accounts => Set<Account>();
    public DbSet<BankTransaction> Transactions => Set<BankTransaction>();
    public DbSet<Consent> Consents => Set<Consent>();
    public DbSet<PendingConsent> PendingConsents => Set<PendingConsent>();
    public DbSet<AuditEntry> Audit => Set<AuditEntry>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        base.OnModelCreating(b);
        b.UseOpenIddict();
        b.Entity<Customer>().HasIndex(c => c.Email).IsUnique();
        b.Entity<Account>().Property(a => a.Balance).HasConversion<double>();
        b.Entity<BankTransaction>().Property(t => t.Amount).HasConversion<double>();
        b.Entity<Consent>().Property(c => c.AccountIds).HasConversion(
            v => string.Join(',', v), v => v.Split(',', StringSplitOptions.RemoveEmptyEntries).ToList());
        b.Entity<Consent>().Property(c => c.Scopes).HasConversion(
            v => string.Join(' ', v), v => v.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList());
        b.Entity<PendingConsent>().Property(c => c.Scopes).HasConversion(
            v => string.Join(' ', v), v => v.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList());
        b.Entity<PendingConsent>().HasIndex(p => p.RequestKey).IsUnique();
    }
}

public class Customer
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Email { get; set; }
    public required string Name { get; set; }
    public string PasswordHash { get; set; } = "";
}

public class Account
{
    public required string Id { get; set; }
    public Guid CustomerId { get; set; }
    public required string Name { get; set; }
    public decimal Balance { get; set; }
    public string Currency { get; set; } = "CAD";
}

public class BankTransaction
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string AccountId { get; set; }
    public DateOnly Date { get; set; }
    public required string Description { get; set; }
    public decimal Amount { get; set; }
}

public enum ConsentStatus { Active, Revoked }

/// <summary>Consentement accordé par un client à une application tierce : portée, comptes, durée.</summary>
public class Consent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid CustomerId { get; set; }
    public required string ClientId { get; set; }
    public required string ClientName { get; set; }
    public List<string> Scopes { get; set; } = [];
    public List<string> AccountIds { get; set; } = [];
    public DateTimeOffset GrantedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public ConsentStatus Status { get; set; } = ConsentStatus.Active;
    public DateTimeOffset? RevokedAt { get; set; }
    public string? AuthorizationId { get; set; }

    public bool IsActiveAt(DateTimeOffset now) => Status == ConsentStatus.Active && now < ExpiresAt;
}

public enum PendingStatus { Pending, Approved, Denied, Used }

/// <summary>Demande d'autorisation en attente de la décision du client sur l'écran de consentement.</summary>
public class PendingConsent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string RequestKey { get; set; }
    public Guid CustomerId { get; set; }
    public required string ClientId { get; set; }
    public required string ClientName { get; set; }
    public List<string> Scopes { get; set; } = [];
    public required string ReturnUrl { get; set; }
    public PendingStatus Status { get; set; } = PendingStatus.Pending;
    public Guid? ConsentId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>Journal d'audit chaîné : chaque entrée contient l'empreinte de la précédente.</summary>
public class AuditEntry
{
    public long Id { get; set; }
    public DateTimeOffset At { get; set; }
    public required string Type { get; set; }
    public required string Actor { get; set; }
    public Guid? CustomerId { get; set; }
    public Guid? ConsentId { get; set; }
    public string Detail { get; set; } = "";
    public string PreviousHash { get; set; } = "";
    public string Hash { get; set; } = "";
}
