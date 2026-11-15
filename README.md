# ConsentBank

[![CI](https://github.com/peacedayou/consentbank/actions/workflows/ci.yml/badge.svg)](https://github.com/peacedayou/consentbank/actions/workflows/ci.yml)

API de **partage de données bancaires avec consentement** du client, dans l'esprit du cadre
fédéral des services bancaires axés sur les consommateurs : le client choisit quoi partager,
avec quelle application et pour combien de temps, et peut tout retirer à tout moment.

**Présentation :** https://peacedayou.github.io/consentbank/

ASP.NET Core 10 · OpenIddict · Entity Framework Core (SQLite) · portail Blazor (rendu serveur)

## Fonctionnalités

- **OAuth 2.0, profil inspiré de FAPI 2.0** : code d'autorisation seulement, **PKCE S256** et
  **requêtes poussées (PAR)** obligatoires, code d'une minute à usage unique, jetons de 10 minutes.
- **Consentement explicite** : portées en français, choix des comptes et de la durée (30, 90
  ou 365 jours), refus possible (`access_denied`).
- **API bancaire** (`/api/v1/comptes`, `/api/v1/comptes/{id}/operations`) : portée vérifiée,
  seuls les comptes consentis sont visibles, opérations limitées à 90 jours.
- **Révocation immédiate** depuis le portail : consentement, autorisation OpenIddict et jetons
  révoqués ; un jeton encore valide est refusé dès l'appel suivant.
- **Journal d'audit chaîné** (SHA-256) : consentements, jetons, consultations, révocations,
  connexions ; le portail affiche le journal et l'état de la chaîne.
- Formulaires protégés contre le CSRF, cookie `HttpOnly`, HTTPS exigé par défaut, secrets
  seulement dans la configuration.

## Ce qui manque pour un vrai FAPI 2.0

Jetons liés à l'émetteur (DPoP ou mTLS), authentification du client par clé
(`private_key_jwt`) et clés de signature gérées. C'est indiqué aussi sur la page de présentation.

## Démarrer

```bash
cp .env.exemple .env      # puis choisissez vos propres valeurs
docker compose up --build
# http://localhost:8080/portail  (alice@exemple.ca, mot de passe de votre .env)
```

## Tests

```bash
dotnet test tests/ConsentBank.Tests/ConsentBank.Tests.csproj
```

Les tests rejouent le parcours complet comme une vraie application tierce et son utilisateur :
PAR → autorisation → connexion → consentement → code → jeton (PKCE) → API, puis les cas
d'erreur (mauvais vérificateur PKCE, code réutilisé, refus, autorisation sans PAR, mauvais
secret), l'expiration, la révocation et la détection d'une altération du journal.

## Licence

MIT
