using ConsentBank.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace ConsentBank.Data;

/// <summary>Données de démonstration : un client, ses comptes et une application tierce (« Budget Futé »).</summary>
public static class Seed
{
    public const string ClientId = "budget-fute";
    public const string RedirectUri = "https://budget-fute.exemple/rappel";

    public static async Task RunAsync(IServiceProvider sp, IConfiguration config)
    {
        var db = sp.GetRequiredService<BankDbContext>();
        await db.Database.EnsureCreatedAsync();

        // Les secrets viennent de la configuration (variables d'environnement), jamais du code.
        var password = config["Demo:MotDePasse"];
        var clientSecret = config["Demo:SecretClient"];
        if (string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(clientSecret))
        {
            throw new InvalidOperationException("Définissez Demo__MotDePasse et Demo__SecretClient (voir README).");
        }

        if (!await db.Customers.AnyAsync())
        {
            var alice = new Customer { Email = "alice@exemple.ca", Name = "Alice Tremblay" };
            alice.PasswordHash = sp.GetRequiredService<IPasswordHasher<Customer>>().HashPassword(alice, password);
            db.Customers.Add(alice);
            db.Accounts.AddRange(
                new Account { Id = "CHQ-001", CustomerId = alice.Id, Name = "Compte chèques", Balance = 2350.40m },
                new Account { Id = "EPA-002", CustomerId = alice.Id, Name = "Épargne", Balance = 12000.00m },
                new Account { Id = "CRD-003", CustomerId = alice.Id, Name = "Carte de crédit", Balance = -412.75m });
            var today = DateOnly.FromDateTime(DateTime.UtcNow);
            db.Transactions.AddRange(
                new BankTransaction { AccountId = "CHQ-001", Date = today.AddDays(-2), Description = "Épicerie", Amount = -86.12m },
                new BankTransaction { AccountId = "CHQ-001", Date = today.AddDays(-5), Description = "Paie", Amount = 1850.00m },
                new BankTransaction { AccountId = "CHQ-001", Date = today.AddDays(-12), Description = "Loyer", Amount = -1100.00m },
                new BankTransaction { AccountId = "CHQ-001", Date = today.AddDays(-120), Description = "Ancienne opération", Amount = -20.00m },
                new BankTransaction { AccountId = "EPA-002", Date = today.AddDays(-30), Description = "Virement d'épargne", Amount = 200.00m });
            await db.SaveChangesAsync();
        }

        var apps = sp.GetRequiredService<IOpenIddictApplicationManager>();
        if (await apps.FindByClientIdAsync(ClientId) is null)
        {
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = ClientId,
                ClientSecret = clientSecret,
                ClientType = ClientTypes.Confidential,
                ConsentType = ConsentTypes.Explicit,
                DisplayName = "Budget Futé",
                RedirectUris = { new Uri(RedirectUri) },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.PushedAuthorization,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.ResponseTypes.Code,
                    Permissions.Prefixes.Scope + ConsentService.Scopes.AccountsRead,
                    Permissions.Prefixes.Scope + ConsentService.Scopes.TransactionsRead,
                },
                Requirements =
                {
                    Requirements.Features.ProofKeyForCodeExchange,
                    Requirements.Features.PushedAuthorizationRequests,
                },
            };
            await apps.CreateAsync(descriptor);
        }
    }
}
