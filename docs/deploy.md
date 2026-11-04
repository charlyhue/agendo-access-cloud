# Déployer le plan de contrôle (Dokploy)

Une application Dokploy de type **Docker** (image `ghcr.io/charlyhue/agendo-access-cloud`),
derrière Traefik, avec une base PostgreSQL Dokploy. L'image ne contient que le binaire et les
certificats CA ; elle écoute en HTTP sur le port 8080 du réseau Docker, Traefik termine le TLS
de `api.DOMAINE` et de `compte.DOMAINE` et route les deux noms vers ce même port.

Le domaine n'est pas encore choisi : partout ci-dessous, `DOMAINE` et `ZONE_MAISONS` sont des
exemples à remplacer.

## 1. Base PostgreSQL

1. Dokploy → *Databases* → *PostgreSQL* (version 17), dans le même projet et le même réseau que
   l'application. Notez l'URL interne (`postgres://utilisateur:motdepasse@hôte:5432/base`).
2. Les migrations s'appliquent au démarrage de `serve` (verrou consultatif : deux instances
   peuvent démarrer en même temps). `agendo-access-cloud migrate` les applique à la main.

## 2. Fichiers montés (secrets)

Aucun secret ne passe par une variable d'environnement : Dokploy → application → *Advanced* →
*Mounts* → *File Mount*, un fichier par secret, monté en lecture seule, par exemple sous
`/run/secrets/`. Chaque variable `…_FILE` donne le chemin du fichier.

| Fichier (exemple) | Contenu | Variable |
|---|---|---|
| `/run/secrets/database-url` | URL interne de la base (mot de passe compris) | `AGENDO_CLOUD_DATABASE_URL_FILE` |
| `/run/secrets/signing-key` | graine Ed25519 du plan de contrôle (base64url), voir 3 | `AGENDO_CLOUD_SIGNING_KEY_FILE` |
| `/run/secrets/resend-api-key` | clé d'API Resend (envoi seul, domaine vérifié) | `AGENDO_CLOUD_RESEND_API_KEY_FILE` |
| `/run/secrets/cloudflare-token` | jeton d'API Cloudflare « DNS : modifier » limité à la zone des maisons | `AGENDO_CLOUD_CLOUDFLARE_TOKEN_FILE` |

L'image tourne sous l'utilisateur 65534 : les fichiers doivent lui être lisibles.

## 3. Clé de signature

Elle signe les jetons de tunnel et push. Créez-la une fois, sur une machine sûre ou dans le
terminal Dokploy de l'application :

```sh
agendo-access-cloud keygen --kid k1 /tmp/signing-key
```

La commande écrit la graine (mode 0600, jamais d'écrasement) et affiche la ligne `k1=<clé
publique>`. Copiez la graine dans le *File Mount* `signing-key`, puis effacez `/tmp/signing-key`.
La ligne `k1=…` va dans la configuration des relais (`RELAY_TRUSTED_KEYS`, dépôt
agendo-access-relays) ; les maisons la reçoivent au rattachement et par
`GET /.well-known/agendo-access/keys`.

**Rotation** sans coupure : créez `k2`, ajoutez `k2=…` aux relais et redéployez-les ; passez
le plan de contrôle sur `k2` (`AGENDO_CLOUD_SIGNING_KID=k2`, nouveau fichier) en gardant
`AGENDO_CLOUD_PUBLISHED_KEYS=k1=…` ; 24 h plus tard (durée des jetons), retirez `k1` partout.

## 4. Variables d'environnement

Obligatoires sauf mention. Aucun domaine ni seuil n'a de valeur par défaut dans le code.

| Variable | Exemple | Rôle |
|---|---|---|
| `AGENDO_CLOUD_LISTEN` | `0.0.0.0:8080` (défaut de l'image) | adresse d'écoute |
| `AGENDO_CLOUD_DATABASE_URL_FILE` | `/run/secrets/database-url` | URL de la base (fichier) |
| `AGENDO_CLOUD_API_URL` | `https://api.exemple.fr` | API des maisons ; `iss` des jetons |
| `AGENDO_CLOUD_PORTAL_URL` | `https://compte.exemple.fr` | portail : origine WebAuthn, RP ID (son hôte), liens des e-mails |
| `AGENDO_CLOUD_ZONE` | `maisons.exemple.fr` | `ZONE_MAISONS` : les maisons sont `<16 base32>.ZONE` |
| `AGENDO_CLOUD_RELAYS` | `tls://relais.exemple.fr` | relais SNI annoncés, séparés par des virgules |
| `AGENDO_CLOUD_PUSH_URLS` | `https://push.exemple.fr` | relais push (URL de base), séparés par des virgules |
| `AGENDO_CLOUD_SIGNING_KEY_FILE` | `/run/secrets/signing-key` | graine de la clé de signature (fichier) |
| `AGENDO_CLOUD_SIGNING_KID` | `k1` | identifiant de la clé courante |
| `AGENDO_CLOUD_PUBLISHED_KEYS` | `k0=…` | facultatif : anciennes clés encore publiées (rotation) |
| `AGENDO_CLOUD_MAILER` | `resend` | `resend`, ou `outbox` en développement |
| `AGENDO_CLOUD_MAIL_FROM` | `Agendo Access <ne-pas-repondre@exemple.fr>` | expéditeur (domaine vérifié chez Resend) |
| `AGENDO_CLOUD_RESEND_API_KEY_FILE` | `/run/secrets/resend-api-key` | clé Resend (fichier) |
| `AGENDO_CLOUD_RESEND_API_URL` | — | facultatif : `https://api.resend.com` par défaut |
| `AGENDO_CLOUD_OUTBOX_DIR` | `/tmp/outbox` | avec `outbox` seulement : un fichier par e-mail |
| `AGENDO_CLOUD_DNS` | `cloudflare` | `cloudflare`, ou `fake` en développement (rien n'est publié) |
| `AGENDO_CLOUD_CLOUDFLARE_ZONE_ID` | `023e1…` | identifiant de la zone qui contient `ZONE_MAISONS` |
| `AGENDO_CLOUD_CLOUDFLARE_TOKEN_FILE` | `/run/secrets/cloudflare-token` | jeton d'API (fichier) |
| `AGENDO_CLOUD_CLOUDFLARE_API_URL` | — | facultatif : `https://api.cloudflare.com/client/v4` par défaut |
| `AGENDO_CLOUD_TRUST_X_FORWARDED_FOR` | `true` | `true` derrière Traefik (IP cliente = dernière entrée de `X-Forwarded-For`), `false` sinon ; les IPv6 sont comptées par /64 |
| `AGENDO_CLOUD_LIMIT_IP_PER_MINUTE` | `30` | cérémonies du portail, rattachements, requêtes de maisons, par IP et par minute |
| `AGENDO_CLOUD_LIMIT_EMAIL_CODES_PER_HOUR` | `5` | codes de connexion envoyés par compte et par heure |
| `AGENDO_CLOUD_LIMIT_HOUSE_PER_MINUTE` | `20` | requêtes signées par maison et par minute (la maison en fait ~1 toutes les 6 h) |
| `AGENDO_CLOUD_PUSH_PER_HOUR` | `60` | quota de notifications par heure, porté par le jeton push |
| `AGENDO_CLOUD_PUSH_CRITICAL_PER_DAY` | `10` | quota d'alertes critiques par jour, porté par le jeton push |
| `RUST_LOG` | `info` | facultatif : filtre des logs (`info,sqlx=warn` par défaut) |

Les logs sont en JSON sur la sortie d'erreur, sans secret : la route est journalisée
(`/invitation/{token}`), jamais l'URI.

## 5. Traefik

Deux domaines sur l'application (Dokploy → *Domains*), port 8080, HTTPS par Let's Encrypt :
`api.exemple.fr` et `compte.exemple.fr`. Le portail exige HTTPS (cookie `__Host-`, WebAuthn).
Le bilan de santé de l'image (`HEALTHCHECK`) appelle `agendo-access-cloud healthcheck`
(`GET /healthz`, qui interroge la base).

## 6. Administration

Dans le terminal Dokploy de l'application (même environnement et mêmes fichiers que `serve`) :

```sh
agendo-access-cloud admin invite personne@exemple.fr   # compte invité, lien de 7 jours par e-mail
agendo-access-cloud admin list
agendo-access-cloud admin suspend personne@exemple.fr  # jetons refusés : subscription_inactive
agendo-access-cloud admin resume personne@exemple.fr
agendo-access-cloud admin revoke-house <hôte ou étiquette>
```

Relancer `invite` sur un compte encore invité renvoie un nouveau lien (l'ancien cesse de valoir).

## 7. Sauvegardes

Dokploy → base PostgreSQL → *Backups* : destination S3 d'un **autre hébergeur** que le VPS
(Dokploy → *Settings* → *Destinations* ; clés d'accès limitées à un seul bucket), sauvegarde
quotidienne, rétention d'au moins 30 jours.

À savoir :

- la base ne contient ni clé privée ni jeton en clair (codes, invitations et sessions sont
  hachés), mais elle contient les adresses e-mail : chiffrement côté serveur du bucket, accès
  restreint ;
- la clé de signature n'est **pas** dans la base : gardez une copie de la graine hors du VPS
  (gestionnaire de mots de passe). Sa perte n'est pas grave (nouvelle clé, publiée aux relais,
  les maisons renouvellent leurs jetons), sa fuite si (rotation immédiate) ;
- **restauration testée** au moins une fois : restaurer la dernière sauvegarde dans une base
  neuve, y pointer une instance de test, `admin list`.

Sans la base, l'accès et les notifications continuent pendant la validité des jetons (24 h) :
les relais vérifient les jetons sans elle.

## 8. Image et CI

`.github/workflows/ci.yml` : tests sur un PostgreSQL de service, clippy, cargo-deny, image ; sur
`main`, push de `ghcr.io/charlyhue/agendo-access-cloud:<sha>` (et `:latest`) puis appel du
webhook Dokploy.

Secrets GitHub Actions du dépôt `charlyhue/agendo-access-cloud` (*Settings* → *Secrets and
variables* → *Actions*) :

| Secret | Contenu |
|---|---|
| `AGENDO_DEPLOY_KEY` | clé privée SSH de déploiement, en lecture sur `charlyhue/agendo` (ci-dessous) |
| `DOKPLOY_WEBHOOK_URL` | URL du webhook de déploiement de l'application (Dokploy → *Deployments*) |

Dans Dokploy, l'application suit `:latest` ; revenir en arrière = passer l'image sur un `:<sha>`
précédent. Dokploy lit GHCR avec un jeton GitHub (*Registry*) limité à `read:packages`.

### Clé de déploiement (dépôt privé du socle)

Le protocole et WebAuthn viennent de `charlyhue/agendo` (privé). `Cargo.toml` les déclare par
le chemin local `file:///Users/chue/workspace/agendo` (branche `agendo-access`) ; la CI et
l'image renvoient cette adresse vers GitHub (`git config url.<GitHub>.insteadOf <file://…>`),
lue avec une clé de déploiement :

1. Poussez la branche du socle sur GitHub : `git -C /Users/chue/workspace/agendo push origin
   agendo-access`. Le commit verrouillé dans `Cargo.lock` doit y être.
2. Créez une paire de clés dédiée, sans phrase de passe :
   `ssh-keygen -t ed25519 -N "" -C "agendo-access-cloud CI" -f agendo-deploy`.
3. `charlyhue/agendo` → *Settings* → *Deploy keys* → *Add deploy key* : collez
   `agendo-deploy.pub`, **sans** « Allow write access ».
4. `charlyhue/agendo-access-cloud` → secret Actions `AGENDO_DEPLOY_KEY` : collez le contenu de
   `agendo-deploy` (clé privée), puis effacez les deux fichiers locaux.

Quand le socle aura une URL GitHub et un tag pour ces crates, `Cargo.toml` passera à
`git = "ssh://git@github.com/charlyhue/agendo.git", tag = "…"` et l'`insteadOf` disparaîtra.

### Construire l'image à la main

```sh
# Depuis GitHub (clé de l'agent SSH) :
docker build --ssh default -t agendo-access-cloud .
# Sans GitHub, depuis le dépôt local du socle :
git clone --bare --single-branch -b agendo-access /Users/chue/workspace/agendo /tmp/agendo.git
docker build --build-context agendo=/tmp/agendo.git --build-arg AGENDO_GIT=file:///agendo -t agendo-access-cloud .
```

## 9. Développement local

```sh
scripts/test.sh                         # PostgreSQL de test en conteneur + cargo test
```

Pour lancer le serveur à la main : une base (par exemple `scripts/db.sh up`, puis une base
créée dedans), un fichier pour son URL, `keygen` pour la clé, `AGENDO_CLOUD_MAILER=outbox`
(les e-mails arrivent en fichiers), `AGENDO_CLOUD_DNS=fake`,
`AGENDO_CLOUD_PORTAL_URL=http://localhost:<port>` (le HTTP n'est accepté que sur la boucle
locale), les seuils ci-dessus, puis `cargo run -- migrate` et `cargo run -- serve`.
