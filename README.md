# Agendo Access : plan de contrôle et portail

Service géré d'**Agendo Access** (accès distant et notifications des maisons Agendo, sur
abonnement). Ce dépôt est privé pour de bon. Il contient :

- le **plan de contrôle** (`api.DOMAINE`) : rattachement des maisons par code, délivrance des
  jetons de tunnel et push (JWS EdDSA), pose des TXT ACME DNS-01 pour les certificats des
  maisons, publication des clés de confiance ;
- le **portail** (`compte.DOMAINE`) : comptes sur invitation, connexion par passkey (code par
  e-mail en secours), liste et rattachement des maisons, gestion du compte ;
- la **CLI d'administration**, lancée dans le conteneur (`agendo-access-cloud admin …`).

Le plan de contrôle reste hors du chemin des données : il ne voit passer ni le trafic des
maisons ni leurs notifications. Les relais (dépôt `agendo-access-relays`) vérifient ses jetons
sans base de données.

La spec qui fait foi vit dans le dépôt du socle :
`docs/superpowers/specs/2026-11-04-agendo-access-design.md` (branche `agendo-access`).

## Stack

Rust (axum, sqlx et ses migrations), PostgreSQL. Le protocole commun (`agendo-access-protocol`)
et la vérification WebAuthn (`agendo-webauthn`) viennent du dépôt `charlyhue/agendo` par Git.

Les conventions de travail sont dans [CLAUDE.md](CLAUDE.md), le déploiement dans
`docs/deploy.md`.
