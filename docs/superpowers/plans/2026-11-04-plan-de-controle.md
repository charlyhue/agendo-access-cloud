# Plan de contrôle et portail d'Agendo Access : plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** livrer le binaire `agendo-access-cloud` : API des maisons (`api.DOMAINE`), portail
(`compte.DOMAINE`) et CLI d'administration, avec image Docker et CI.

**Architecture:** un crate (bibliothèque et binaire). axum sert l'API et le portail sur le même
port : `/v1/*` et `/.well-known/*` pour les maisons, tout le reste pour le portail. Il est sans
état hors de PostgreSQL : défis WebAuthn et compteurs de débit sont en base, si bien que deux
instances peuvent tourner. Les effets extérieurs passent par des traits (`Mailer`, `DnsProvider`,
`Clock`), avec des implémentations factices pour les tests.

**Tech Stack:** Rust 2024, axum 0.8, sqlx 0.9 (PostgreSQL, migrations, requêtes à l'exécution,
sans `query!` ni `DATABASE_URL` à la compilation), askama (gabarits HTML échappés), reqwest
(rustls avec ring) pour Resend et Cloudflare, clap pour la CLI, tracing en JSON.
`agendo-access-protocol` et `agendo-webauthn` par Git
(`file:///Users/chue/workspace/agendo`, branche `agendo-access`).

**Spec:** `git -C /Users/chue/workspace/agendo show agendo-access:docs/superpowers/specs/2026-11-04-agendo-access-design.md`

## Global Constraints

- Tout en français : logs, commentaires, docs, pages, e-mails.
- Aucun secret dans le code, Git, `.env` ni les logs. Les secrets arrivent par des fichiers
  montés (`…_FILE`). Aucun domaine en dur, aucun seuil anti-abus en dur : variables
  d'environnement obligatoires.
- Le tracing journalise la route (`MatchedPath`), jamais l'URI brute : `/invitation/<jeton>`
  porte un secret.
- Constantes de la spec : invitation 7 jours, usage unique ; code e-mail à 6 chiffres, 10 min,
  5 essais ; session 30 jours, cookie `Secure; HttpOnly; SameSite=Lax` ; code de rattachement
  `ENROLLMENT_CODE_LEN`/`ENROLLMENT_CODE_ALPHABET`/`ENROLLMENT_CODE_TTL_SECS` du protocole ;
  étiquette de maison de 16 caractères base32 (`HOUSE_LABEL_*`), jamais réattribuée ; jetons de
  `TOKEN_LIFETIME_SECS` (24 h) ; signature à ±60 s (`verify_request`).
- Jetons d'invitation, codes et sessions sont hachés (SHA-256) en base. Aucun jeton de
  téléphone, aucun contenu de maison.
- Abonnement : `accounts.subscription_active` et `subscription_source` (`manual`).
- Refus de l'API : corps `Refusal` du protocole. Statuts : `subscription_inactive`/`revoked`
  403, `bad_signature` 401, `rate_limited` 429, `bad_request` et `invalid_code` 400.
- `cargo clippy --all-targets -- -D warnings` sans warning ; aucun `unwrap` sur une donnée
  réseau.
- Ne jamais modifier le dépôt agendo.

## Décisions prises ici (à signaler dans la PR)

- **`Agendo-House: <house_id>`** : en-tête ajouté aux requêtes signées. `Agendo-Signature` ne
  dit pas quelle maison signe, et le corps de `tokens` est vide. Il n'est pas signé : un
  identifiant faux fait échouer la vérification. C'est un besoin sur le protocole : une
  constante `HOUSE_HEADER` dans le crate et une ligne dans la spec.
- `invalid_code` répond 400 (la spec ne fixe pas le statut).
- `admin suspend` met `subscription_active = false` (jetons refusés en
  `subscription_inactive`). Le portail reste ouvert pour l'export et la suppression.
- Code e-mail réservé aux comptes `active`. Un compte `invited` reçoit une nouvelle
  invitation par `admin invite`.
- Suppression d'un compte : ses maisons sont révoquées et détachées (`account_id NULL`, nom
  effacé). La ligne reste, pour que l'étiquette ne soit jamais réattribuée.
- Le dernier passkey d'un compte ne se retire pas.
- Clé de signature : graine Ed25519 en base64url dans un fichier monté, `kid` par variable ;
  `keygen` la crée. Clés anciennes encore publiées : `AGENDO_CLOUD_PUBLISHED_KEYS`.
- L'URL de l'API Resend et celle de Cloudflare ont une valeur par défaut, l'adresse publique du
  fournisseur, qu'une variable peut remplacer. Ce ne sont pas nos domaines.

## Review Focus

1. Code de rattachement saisi en minuscules, avec espaces ou tirets : accepté (Tâche 8,
   `enroll_accepts_loose_code`).
2. Même code utilisé deux fois : la seconde fois répond `invalid_code`, une seule maison est
   créée (Tâche 8, `enroll_code_single_use`).
3. E-mail invité avec une autre casse : le même compte (Tâche 3,
   `invite_normalizes_email` ; Tâche 4, `code_login_ignores_case`).
4. Horloge de la maison décalée de plus de 60 s, ou chemin avec `?…` : 401 `bad_signature`
   avec détail, et chemin complet signé (Tâche 9, `tokens_refuse_stale_signature`,
   `signature_covers_query`).
5. Lien d'invitation expiré ou déjà utilisé, rejoué : une page d'erreur en français, jamais
   un 500 (Tâche 5, `invitation_expired_or_used`).

---

## File Structure

```
Cargo.toml, deny.toml, rust-toolchain.toml
migrations/0001_initial.sql      schéma complet
scripts/db.sh                    PostgreSQL de test en conteneur (up|down|url)
scripts/test.sh                  lance db.sh up puis cargo test avec DATABASE_URL
src/main.rs                      CLI clap : serve, migrate, keygen, healthcheck, admin …
src/lib.rs                       modules, `app(state) -> Router`
src/config.rs                    Config::from_env, lecture des secrets `…_FILE`
src/clock.rs                     Clock, SystemClock, ManualClock
src/crypto.rs                    aléa, hachage, codes, étiquettes
src/state.rs                     AppState
src/db/{accounts,auth,houses,audit,rate_limit}.rs
src/mail.rs                      Mailer, Resend, Outbox, Memory
src/dns.rs                       DnsProvider, Cloudflare, Fake
src/signing.rs                   clé du plan de contrôle, émission des jetons
src/api/{mod,signed}.rs          API des maisons
src/portal/{mod,session,login,webauthn,houses,account}.rs
src/admin.rs                     commandes d'administration (testables)
templates/*.html                 askama
static/{portail.css,webauthn.js}
tests/common/mod.rs              TestApp
tests/*.rs                       #[sqlx::test]
Dockerfile, .dockerignore, .github/workflows/ci.yml, docs/deploy.md
```

## Schéma (Tâche 1, `migrations/0001_initial.sql`)

| Table | Colonnes |
|---|---|
| `accounts` | `id uuid pk`, `email text unique` (minuscules), `status text` (`invited`/`active`), `subscription_active bool`, `subscription_source text` (`manual`), `webauthn_user_id bytea unique`, `created_at`, `activated_at?` |
| `invitations` | `id`, `account_id → accounts cascade`, `token_hash bytea unique`, `created_at`, `expires_at`, `consumed_at?` |
| `passkeys` | `id`, `account_id cascade`, `credential_id bytea unique`, `public_key bytea`, `algorithm bigint`, `sign_count bigint`, `backup_eligible bool`, `transports text[]`, `name text`, `created_at`, `last_used_at?` |
| `sessions` | `id`, `account_id cascade`, `token_hash bytea unique`, `user_agent text`, `created_at`, `expires_at`, `last_seen_at`, `revoked_at?` |
| `email_codes` | `id`, `account_id cascade`, `code_hash bytea`, `created_at`, `expires_at`, `attempts int`, `consumed_at?` |
| `webauthn_challenges` | `challenge bytea pk`, `purpose text`, `account_id? cascade`, `invitation_id? cascade`, `expires_at` |
| `houses` | `id uuid pk`, `account_id? → accounts set null`, `label text unique`, `host text unique`, `name text`, `public_key text unique`, `enrolled_at`, `revoked_at?`, `last_token_at?` |
| `enrollment_codes` | `id`, `account_id cascade`, `code_hash bytea unique`, `created_at`, `expires_at`, `consumed_at?`, `house_id?` |
| `audit` | `id bigserial`, `at`, `account_id? set null`, `house_id? set null`, `event text`, `detail jsonb` |
| `rate_limits` | `key text`, `window_start timestamptz`, `count int`, pk (`key`, `window_start`) |

Toutes les dates sont des `timestamptz` fournies par `Clock`, jamais `now()` SQL.

## Configuration (Tâche 1, `src/config.rs`)

| Variable | Rôle |
|---|---|
| `AGENDO_CLOUD_LISTEN` | adresse d'écoute (`0.0.0.0:8080` par défaut) |
| `AGENDO_CLOUD_DATABASE_URL_FILE` | fichier contenant l'URL PostgreSQL (secret) |
| `AGENDO_CLOUD_API_URL` | `https://api.DOMAINE`, `iss` des jetons |
| `AGENDO_CLOUD_PORTAL_URL` | `https://compte.DOMAINE` : origine WebAuthn, RP ID = son hôte, liens des e-mails |
| `AGENDO_CLOUD_ZONE` | `ZONE_MAISONS` |
| `AGENDO_CLOUD_RELAYS` | `tls://…` séparés par des virgules (validés par `RelayAddr::parse`) |
| `AGENDO_CLOUD_PUSH_URLS` | `https://…` séparés par des virgules |
| `AGENDO_CLOUD_SIGNING_KEY_FILE`, `AGENDO_CLOUD_SIGNING_KID` | clé de signature |
| `AGENDO_CLOUD_PUBLISHED_KEYS` | `kid=clé,…` supplémentaires publiées (rotation), facultatif |
| `AGENDO_CLOUD_MAILER` | `resend` ou `outbox` (dev) ; `AGENDO_CLOUD_OUTBOX_DIR` |
| `AGENDO_CLOUD_RESEND_API_KEY_FILE`, `AGENDO_CLOUD_MAIL_FROM`, `AGENDO_CLOUD_RESEND_API_URL?` | Resend |
| `AGENDO_CLOUD_DNS` | `cloudflare` ou `fake` (dev) |
| `AGENDO_CLOUD_CLOUDFLARE_TOKEN_FILE`, `AGENDO_CLOUD_CLOUDFLARE_ZONE_ID`, `AGENDO_CLOUD_CLOUDFLARE_API_URL?` | Cloudflare |
| `AGENDO_CLOUD_TRUST_X_FORWARDED_FOR` | `true` derrière Traefik : IP cliente = dernière entrée |
| `AGENDO_CLOUD_LIMIT_IP_PER_MINUTE` | cérémonies du portail et `enroll`, par IP |
| `AGENDO_CLOUD_LIMIT_EMAIL_CODES_PER_HOUR` | codes envoyés par compte |
| `AGENDO_CLOUD_LIMIT_HOUSE_PER_MINUTE` | requêtes signées par maison |
| `AGENDO_CLOUD_PUSH_PER_HOUR`, `AGENDO_CLOUD_PUSH_CRITICAL_PER_DAY` | quotas mis dans le jeton push |
| `RUST_LOG` | filtre des logs |

`Config::from_env()` lit tout ; `Config::for_tests()` (pub) donne des valeurs d'exemple
(`exemple.fr`) pour les tests. Les commandes `admin` n'exigent que la base, le portail et le
courrier : chaque sous-commande lit seulement ce qu'elle utilise
(`Config::database_url()`, `MailConfig::from_env()`, etc.).

---

### Task 1 : socle (crate, configuration, base, serveur, tests)

**Files:** `Cargo.toml`, `rust-toolchain.toml`, `migrations/0001_initial.sql`,
`src/{main,lib,config,clock,state}.rs`, `scripts/{db,test}.sh`, `tests/common/mod.rs`,
`tests/health.rs`, `CLAUDE.md` (commandes).

**Interfaces — Produces:**
- `pub trait Clock: Send + Sync { fn now(&self) -> DateTime<Utc>; }`, `SystemClock`,
  `ManualClock::new(t)` avec `set`/`advance(Duration)`.
- `pub struct AppState { pub db: PgPool, pub config: Arc<Config>, pub clock: Arc<dyn Clock>, pub mailer: Arc<dyn Mailer>, pub dns: Arc<dyn DnsProvider>, pub signer: Arc<Signer> }`
  (`Mailer`, `DnsProvider`, `Signer` arrivent en stubs ici, et sont étoffés aux tâches 3, 7 et 9).
- `pub fn app(state: AppState) -> Router`, `GET /healthz` → `200 "ok"` après `SELECT 1`.
- `tests/common::TestApp::new(pool).await` : état de test (ManualClock à `2026-11-04T12:00Z`,
  MemoryMailer, FakeDns, Signer de graine `[1; 32]` kid `k1`), puis `get`, `post_form`,
  `post_json`, et des requêtes portant cookie et en-têtes.

- [ ] Test `health_ok` (`#[sqlx::test]`) : `GET /healthz` → 200 ; FAIL (rien n'existe).
- [ ] Implémenter le schéma, la config, le serveur, `serve` (migrations au démarrage, arrêt
  propre sur SIGTERM), `migrate` ; `scripts/db.sh` : conteneur `postgres:17-alpine`
  `agendo-access-cloud-pg` sur `127.0.0.1:${AGENDO_CLOUD_PG_PORT:-54340}`,
  `POSTGRES_HOST_AUTH_METHOD=trust` (base jetable locale, aucun mot de passe).
- [ ] `scripts/test.sh` → PASS ; tests de `config` : variable manquante → erreur qui nomme la
  variable ; relais mal formé refusé.
- [ ] Commit.

### Task 2 : outils (aléa, hachage, débit, journal d'audit)

**Files:** `src/crypto.rs`, `src/db/{rate_limit,audit}.rs`, `tests/rate_limit.rs`.

**Produces:**
- `crypto::random_token() -> String` (32 octets en base64url), `crypto::hash(s: &str) -> Vec<u8>`
  (SHA-256), `crypto::six_digit_code() -> String`, `crypto::enrollment_code() -> String`,
  `crypto::house_label() -> String`.
- `rate_limit::hit(db, key: &str, window: Duration, limit: u32, now) -> Result<bool>`
  (`true` = autorisé ; fenêtre fixe, `INSERT … ON CONFLICT DO UPDATE SET count = count + 1 RETURNING count`).
- `audit::record(db, event: &str, account: Option<Uuid>, house: Option<Uuid>, detail: Value)`.

- [ ] Tests : `house_label` vérifie `is_house_label`, `enrollment_code` passe
  `normalize_enrollment_code` tel quel, `six_digit_code` a 6 chiffres ; `rate_limit` :
  `limit` passages puis refus, nouvelle fenêtre permise après `window`.
- [ ] Implémenter, PASS, commit.

### Task 3 : comptes, invitations, courrier, CLI d'administration

**Files:** `src/db/accounts.rs`, `src/mail.rs`, `src/admin.rs`, `src/main.rs`,
`tests/admin.rs`, `tests/mail.rs`.

**Produces:**
- `#[async_trait] pub trait Mailer { async fn send(&self, mail: Mail) -> anyhow::Result<()>; }`,
  `Mail { to, subject, text, html }` ; `MemoryMailer` (`sent() -> Vec<Mail>`),
  `OutboxMailer(dir)`, `ResendMailer { api_url, key, from }`.
- `admin::invite(&AppState, email) -> anyhow::Result<String>`, `list`, `suspend`, `resume`,
  `revoke_house(host_or_label)` (la dernière vient en Tâche 8), qui rendent le texte affiché.
- Lien `{PORTAL_URL}/invitation/{jeton}`.

- [ ] Tests : `invite_creates_account_and_mails` (compte `invited`, abonnement actif source
  `manual`, un e-mail dont le lien porte un jeton dont le hachage est en base, expiration
  7 j) ; `invite_normalizes_email` (`Alice@Exemple.fr` puis `alice@exemple.fr` donnent le
  même compte, une seconde invitation qui annule la première) ; `invite_refuses_active` ;
  `suspend_resume` ; `list` affiche e-mail, état, abonnement, nombre de maisons ;
  `resend_posts_email` (serveur axum local qui reçoit `POST /emails`, `Authorization: Bearer`,
  JSON `from,to,subject,text,html`) ; une erreur Resend donne une erreur sans le corps.
- [ ] Implémenter, sous-commandes clap `admin invite|list|suspend|resume|revoke-house`, PASS,
  commit.

### Task 4 : portail, sessions et connexion par code

**Files:** `src/portal/{mod,session,login}.rs`, `templates/{base,connexion,code,erreur}.html`,
`static/portail.css`, `tests/portal_login.rs`.

**Produces:**
- Cookie `__Host-agendo-session` (jeton aléatoire, `Path=/; Secure; HttpOnly; SameSite=Lax`,
  `Max-Age` 30 j), `sessions::create(db, account, user_agent, now) -> String`.
- Extracteur `CurrentAccount { account_id, session_id, email }` : redirection 303 vers
  `/connexion` sans session valide.
- Middleware : en-têtes de sécurité (CSP `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`,
  `nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`) ; refus 403 de toute
  requête non GET du portail dont l'`Origin` n'est pas celle du portail.
- Routes : `GET /connexion`, `POST /connexion/code` (`email`), `POST /connexion/code/verifier`
  (`email`, `code`), `POST /deconnexion`, `GET /` → `/maisons`.

- [ ] Tests : `code_login_flow` (code envoyé, vérifié, cookie posé, `/maisons` accessible) ;
  `code_login_ignores_case` ; `unknown_email_same_answer` (même page, aucun e-mail) ;
  `code_expires_after_10_min` ; `code_five_attempts` (le 6ᵉ essai, même correct, est refusé) ;
  `code_rate_limited` ; `cross_origin_post_refused` ; `logout_revokes_session` ;
  `security_headers_present`.
- [ ] Implémenter, PASS, commit.

### Task 5 : passkeys (invitation, connexion, gestion)

**Files:** `src/portal/webauthn.rs`, `src/db/auth.rs`, `templates/{invitation}.html`,
`static/webauthn.js`, `tests/portal_passkeys.rs`.

**Produces:**
- `POST /invitation/{jeton}/options` → `PublicKeyCredentialCreationOptions` en JSON
  (base64url) : `rp {id, name: "Agendo Access"}`, `user {id: webauthn_user_id, name: email}`,
  `pubKeyCredParams` = `agendo_webauthn::ALGORITHMS`,
  `authenticatorSelection {residentKey: "required", userVerification: "required"}`,
  `attestation: "none"`, `excludeCredentials` ; défi en base (5 min, usage unique).
- `POST /invitation/{jeton}/terminer` (JSON `RegistrationCredential` + `name`) →
  `verify_registration`, passkey enregistrée, compte `active`, invitation consommée, session
  ouverte → `{ "redirect": "/maisons" }`.
- `POST /connexion/passkey/options` (sans `allowCredentials`), `POST /connexion/passkey/terminer`
  (`verify_assertion`, compteur mis à jour).
- `POST /compte/passkeys/options`, `POST /compte/passkeys/terminer`,
  `POST /compte/passkeys/{id}/retirer`.
- `webauthn.js` : un seul script, lit `data-*`, convertit base64url ↔ `ArrayBuffer`, envoie
  `rawId`, `response.{clientDataJSON, authenticatorData (getAuthenticatorData()), publicKey (getPublicKey()), publicKeyAlgorithm, transports}`
  ou `response.{clientDataJSON, authenticatorData, signature, userHandle}`.

- [ ] Tests avec `agendo_webauthn::soft::Authenticator` : `invitation_registers_passkey` ;
  `invitation_expired_or_used` (page d'erreur 410, jamais 500) ; `passkey_login` ;
  `passkey_login_unknown_credential` (401) ; `challenge_single_use` ; `wrong_origin_refused` ;
  `add_and_remove_passkey` ; `cannot_remove_last_passkey`.
- [ ] Implémenter, PASS, commit.

### Task 6 : compte (sessions, export, suppression)

**Files:** `src/portal/account.rs`, `templates/compte.html`, `tests/portal_account.rs`.

**Produces:** `GET /compte` (passkeys, sessions, boutons) ; `POST /compte/sessions/{id}/revoquer` ;
`GET /compte/export` (JSON joint : compte, passkeys sans clé, sessions sans hachage, maisons,
audit) ; `POST /compte/supprimer` (`confirmation` = e-mail du compte).

- [ ] Tests : `revoke_other_session` ; `export_contains_no_secret` (aucun hachage, aucune clé
  publique de passkey) ; `delete_account_detaches_houses` (le compte disparaît, la maison est
  révoquée avec `account_id NULL` et un nom vide, l'étiquette reste prise) ;
  `delete_requires_confirmation`.
- [ ] Implémenter, PASS, commit.

### Task 7 : clé de signature et jetons

**Files:** `src/signing.rs`, `src/api/mod.rs`, `src/main.rs` (`keygen`), `tests/keys.rs`.

**Produces:**
- `Signer { kid, key: SigningKey, published: TrustedKeys }`, `Signer::from_seed_file(path, kid, published)`,
  `Signer::trusted() -> Vec<TrustedKey>` (clé courante en tête, puis les publiées),
  `Signer::issue(house: &House, now, quotas) -> TokensResponse` (les relais et URL push
  venant de la config).
- `keygen <fichier>` : écrit la graine (mode 0600, refuse d'écraser), affiche `kid=clé publique`.
- `GET /.well-known/agendo-access/keys` → `KeysResponse`.

- [ ] Tests : `keys_endpoint_lists_current_and_published` ; `issued_tokens_verify` (vérifiés
  par `TunnelClaims::verify` et `PushClaims::verify`, `exp = iat + TOKEN_LIFETIME_SECS`,
  quotas de la config) ; `seed_file_errors` (fichier absent ou mal encodé : erreur qui nomme
  le fichier, sans son contenu) ; `keygen_refuses_overwrite`.
- [ ] Implémenter, PASS, commit.

### Task 8 : rattachement des maisons

**Files:** `src/db/houses.rs`, `src/api/mod.rs`, `src/portal/houses.rs`,
`templates/maisons.html`, `src/admin.rs`, `tests/enroll.rs`.

**Produces:**
- Portail : `GET /maisons` (nom, nom d'hôte, rattachée le, dernier jeton, état),
  `POST /maisons/rattacher` → page qui affiche le code `XXXX-XXXX` et son expiration (refus si
  l'abonnement est inactif), `POST /maisons/{id}/revoquer`.
- API : `POST /v1/houses/enroll` (`EnrollRequest`) → `EnrollResponse` ; limite par IP ; code
  consommé par `UPDATE … WHERE consumed_at IS NULL AND expires_at > $now RETURNING` ;
  étiquette tirée de nouveau en cas de collision ; `house_key` validée par
  `decode_public_key` ; nom réduit aux blancs extérieurs, 1 à `MAX_HOUSE_NAME_LEN` octets, sans
  caractère de contrôle.
- `admin::revoke_house`.

- [ ] Tests : `enroll_flow` (le code du portail donne une maison avec
  `host_in_zone(host, zone)`, des relais et URL push de la config, et des `trusted_keys`) ;
  `enroll_accepts_loose_code` ; `enroll_code_single_use` ; `enroll_code_expired` (15 min) ;
  `enroll_bad_key_or_name` (400 `bad_request`) ; `enroll_subscription_inactive` (403) ;
  `portal_revoke_house` ; `admin_revoke_house` ; `houses_of_other_account_hidden`.
- [ ] Implémenter, PASS, commit.

### Task 9 : API signée (jetons, ACME, DNS)

**Files:** `src/api/signed.rs`, `src/dns.rs`, `tests/house_api.rs`, `tests/cloudflare.rs`.

**Produces:**
- Extracteur `SignedHouse { house: House, body: Bytes }` : limite par IP, en-tête
  `Agendo-House`, maison chargée, `verify_request(header, METHOD, path_and_query, body, now, key)`,
  puis limite par maison. Toute erreur rend 401 `bad_signature` (avec `detail`) ou 429.
- `POST /v1/houses/tokens` → `TokensResponse`, met à jour `last_token_at` ; 403 `revoked` ou
  `subscription_inactive`.
- `POST`/`DELETE /v1/houses/acme` (`AcmeRequest`, valeur base64url de 1 à 255 caractères) →
  `DnsProvider::put_txt` ou `delete_txt` sur `_acme-challenge.<host>` → 204.
- `#[async_trait] pub trait DnsProvider { async fn put_txt(&self, name, value); async fn delete_txt(&self, name, value); }` ;
  `FakeDns` (`records() -> Vec<(String, String)>`) ;
  `CloudflareDns { api_url, token, zone_id }` (`POST /zones/{z}/dns_records` TXT ttl 60 ;
  retrait : `GET …?type=TXT&name=…`, filtre sur le contenu, `DELETE` de chacun).

- [ ] Tests : `tokens_flow` ; `tokens_refuse_stale_signature` ; `signature_covers_query` ;
  `tokens_unknown_house` (401) ; `tokens_revoked` / `tokens_subscription_inactive` (403) ;
  `tokens_rate_limited` (429) ; `acme_put_and_delete` (FakeDns contient puis ne contient plus
  `_acme-challenge.<host>`) ; `acme_bad_value` (400) ; `cloudflare_put_delete` (serveur axum
  local qui vérifie `Authorization: Bearer`, le corps et les `DELETE`).
- [ ] Implémenter, PASS, commit.

### Task 10 : bout en bout, image, CI, déploiement

**Files:** `tests/end_to_end.rs`, `Dockerfile`, `.dockerignore`, `deny.toml`,
`.github/workflows/ci.yml`, `docs/deploy.md`, `src/main.rs` (`healthcheck`), `README.md`.

- [ ] `end_to_end` : `admin invite`, passkey par l'invitation, code de rattachement, `enroll`
  avec la clé `[2; 32]`, jetons vérifiés par le protocole avec les clés de `KEYS_PATH`, TXT
  ACME, `admin suspend` → 403 `subscription_inactive`, `admin resume` → jetons,
  `admin revoke-house` → 403 `revoked`.
- [ ] `healthcheck` : `GET /healthz` sur `AGENDO_CLOUD_LISTEN` en HTTP brut (`HEALTHCHECK`
  de l'image scratch).
- [ ] Dockerfile : cargo-chef (`planner`, `cook` puis `build`) sur `rust:alpine`, git
  `insteadOf` qui renvoie `file:///Users/chue/workspace/agendo` vers `AGENDO_GIT` (par défaut
  `ssh://git@github.com/charlyhue/agendo.git`), `--mount=type=ssh`,
  `CARGO_NET_GIT_FETCH_WITH_CLI=true`, binaire musl statique ; image `scratch` avec certificats
  CA, utilisateur 65534.
- [ ] CI : PostgreSQL 17 en service ; clé de déploiement (`webfactory/ssh-agent`, secret
  `AGENDO_DEPLOY_KEY`) avec le même `insteadOf` ; puis clippy `-D warnings`, tests, cargo-deny,
  `docker build` (`ssh: default`). Sur `main` seulement : push `ghcr.io/charlyhue/agendo-access-cloud:<sha>`
  (et `:latest`) et `curl` du webhook `DOKPLOY_WEBHOOK_URL` (secret).
- [ ] `docs/deploy.md` : variables, fichiers montés, création de la clé, réseau Traefik,
  sauvegardes Dokploy de PostgreSQL vers S3 avec un test de restauration, clé de
  déploiement, push de la branche `agendo-access` du socle.
- [ ] Vérification complète (tests, clippy, cargo-deny, `docker build`), commit, PR.
