# Déployer le plan de contrôle (Dokploy)

Une application Dokploy de type **Docker** (image `ghcr.io/charlyhue/agendo-access-cloud`),
derrière Traefik, avec une base PostgreSQL Dokploy. L'image ne contient que le binaire et les
certificats CA ; elle écoute en HTTP sur le port 8080 du réseau Docker, Traefik termine le TLS
de l'API et du portail et route les deux noms vers ce même port.

La configuration complète d'exemple est [`deploy/exemple.env`](../deploy/exemple.env) (vérifiée
par `tests/example_config.rs`). Les domaines qu'elle et ce guide citent sont **temporaires** :
le code n'en contient aucun, tout passe par les variables (section 5).

## 1. Domaines et DNS

### Noms (temporaires)

| Rôle | Nom | Variable |
|---|---|---|
| Maisons | `<id>.agendo.charly-hue.fr` (`<id>` : 16 caractères base32) | `AGENDO_CLOUD_ZONE=agendo.charly-hue.fr` |
| API des maisons (plan de contrôle) | `agendo-api.charly-hue.fr` | `AGENDO_CLOUD_API_URL` |
| Portail ; RP ID WebAuthn ; cookie `__Host-` | `agendo-account.charly-hue.fr` | `AGENDO_CLOUD_PORTAL_URL` |
| Relais SNI (tunnels des maisons) | `agendo-relay-1.charly-hue.fr`, puis `-2`, … | `AGENDO_CLOUD_RELAYS` (`tls://…`) |
| Relais push | `agendo-push-1.charly-hue.fr`, puis `-2`, … | `AGENDO_CLOUD_PUSH_URLS` (`https://…`) |

Les listes `AGENDO_CLOUD_RELAYS` et `AGENDO_CLOUD_PUSH_URLS` sont celles que le plan de contrôle
renvoie aux maisons (rattachement, renouvellement des jetons) : en V1, seulement les `-1`.
Ajouter un relais = le déployer, ajouter son nom aux enregistrements ci-dessous, puis à la
liste ; les maisons le prennent à leur prochain renouvellement (6 h au plus).

### Enregistrements (V1 : tout dans la zone Cloudflare `charly-hue.fr`)

Choix de la personne pour la V1 (trois maisons, domaine temporaire) : **pas de délégation**,
tout vit dans la zone Cloudflare `charly-hue.fr`. Tous les enregistrements sont en
**« DNS only » (nuage gris)**. Proxifié par Cloudflare, un nom verrait son TLS terminé chez
Cloudflare : le relais SNI ne verrait plus le ClientHello des maisons, le certificat de la
maison ne servirait plus, et `X-Forwarded-For` donnerait l'IP de Cloudflare au lieu de celle du
client.

```text
agendo-api       A/AAAA  <IP du VPS Dokploy>        DNS only
agendo-account   A/AAAA  <IP du VPS Dokploy>        DNS only
agendo-relay-1   A/AAAA  <IP du relais 1>           DNS only   # le VPS Dokploy en V1
agendo-push-1    A/AAAA  <IP du relais push 1>      DNS only
*.agendo         A/AAAA  <IP de chaque relais SNI>  DNS only   # une ligne par relais : le joker vers tous
```

Le plan de contrôle pose et retire lui-même les TXT `_acme-challenge.<id>.agendo` des
certificats des maisons (deux valeurs au plus par nom).

**Jeton d'API Cloudflare** (*My Profile* → *API Tokens* → *Create Token*, modèle « Edit zone
DNS ») : permission *Zone → DNS → Edit*, ressource *Specific zone → charly-hue.fr*, rien
d'autre. On peut en plus le limiter aux IP du VPS (*Client IP Address Filtering*). Il va en
*File Mount* (section 3) ; `AGENDO_CLOUD_CLOUDFLARE_ZONE_ID` est l'identifiant de la zone
`charly-hue.fr` (page *Overview* de la zone).

**Ce que ce choix accepte.** Cloudflare ne limite pas un jeton à une partie d'une zone : ce
jeton peut modifier **tout** `charly-hue.fr` (site, courrier, autres projets). Un plan de
contrôle compromis pourrait donc changer n'importe quel enregistrement du domaine, ou faire
émettre un certificat pour n'importe lequel de ses noms. C'est acceptable pour trois maisons de
la personne sur un domaine temporaire ; à ne pas reprendre pour le domaine définitif (voir plus
bas). Un CAA `0 issue "letsencrypt.org"` sur `charly-hue.fr` limite au moins l'émission à Let's
Encrypt, si les autres usages du domaine le permettent.

**À savoir : le joker et les défis ACME.** Un joker ne s'applique pas à un nom qui existe
(RFC 4592). Or poser `_acme-challenge.<id>.agendo.charly-hue.fr` fait exister `<id>.agendo…`
(nœud vide) : tant que ce TXT existe, `<id>.agendo.charly-hue.fr` peut ne plus résoudre par le
joker. C'est une coupure de quelques minutes à chaque renouvellement de certificat (tous les ~60
jours), et elle dure si un TXT n'est jamais retiré (maison arrêtée pendant le défi). À vérifier
sur Cloudflare au premier certificat (`dig A <id>.agendo.charly-hue.fr` pendant le défi). Suivi
possible : poser un `A`/`AAAA` explicite par maison au rattachement, au lieu du seul joker.

### Plus tard : sous-zone déléguée pour le domaine définitif

Pour isoler le jeton DNS du reste du domaine : déléguer la zone des maisons (par exemple
`agendo.<domaine>`) par des enregistrements `NS` (et `DS` si DNSSEC) à une zone séparée, et
donner au `DnsProvider` un jeton limité à elle. Un plan de contrôle compromis ne pourrait plus
alors faire émettre de certificats que pour les maisons. Cloudflare n'héberge une telle
sous-zone qu'avec l'offre Enterprise : il faudra soit un autre fournisseur pour elle (une
nouvelle implémentation de `DnsProvider`, `put_txt` et `delete_txt`), soit un domaine
enregistré à part, dédié aux maisons, qui forme sa propre zone Cloudflare.

### Domaines temporaires : ce qui changera avec eux

- **Passkeys du portail** : elles sont liées au RP ID `agendo-account.charly-hue.fr`. Avec un
  autre nom de portail, elles ne valent plus. Les personnes se reconnectent par code e-mail,
  puis enregistrent une nouvelle passkey (page Compte).
- **Maisons** : leur nom d'hôte complet (`<id>.agendo.charly-hue.fr`) est rangé au
  rattachement, et leurs certificats et jetons le portent. Changer `AGENDO_CLOUD_ZONE` ne
  renomme pas les maisons existantes : il faut les rattacher de nouveau.
- **Jetons** : `iss` vaut `AGENDO_CLOUD_API_URL` ; les maisons et les relais le suivent par
  la configuration.
- **Isolement** : tant que `agendo.charly-hue.fr` n'est pas sur la Public Suffix List, les
  maisons sont « même site » que le portail et que tout `charly-hue.fr`. Le cookie `__Host-`
  du portail ne peut pas être écrasé par un autre sous-domaine, et le portail exige son
  `Origin` sur tout POST. Let's Encrypt compte les certificats des maisons sur la limite de
  `charly-hue.fr` (50 par semaine, avec les autres usages du domaine). Sans gêne pour trois
  maisons. L'inscription à la Public Suffix List se fera sur le domaine définitif.

## 2. Base PostgreSQL

1. Dokploy → *Databases* → *PostgreSQL* (version 17), dans le même projet et le même réseau que
   l'application. Notez l'URL interne (`postgres://utilisateur:motdepasse@hôte:5432/base`).
2. Les migrations s'appliquent au démarrage de `serve` (verrou consultatif : deux instances
   peuvent démarrer en même temps). `agendo-access-cloud migrate` les applique à la main.

## 3. Fichiers montés (secrets)

Aucun secret ne passe par une variable d'environnement : Dokploy → application → *Advanced* →
*Mounts* → *File Mount*, un fichier par secret, monté en lecture seule, par exemple sous
`/run/secrets/`. Chaque variable `…_FILE` donne le chemin du fichier.

| Fichier (exemple) | Contenu | Variable |
|---|---|---|
| `/run/secrets/database-url` | URL interne de la base (mot de passe compris) | `AGENDO_CLOUD_DATABASE_URL_FILE` |
| `/run/secrets/signing-key` | graine Ed25519 du plan de contrôle (base64url), voir 4 | `AGENDO_CLOUD_SIGNING_KEY_FILE` |
| `/run/secrets/resend-api-key` | clé d'API Resend (envoi seul, domaine vérifié) | `AGENDO_CLOUD_RESEND_API_KEY_FILE` |
| `/run/secrets/dns-token` | jeton d'API Cloudflare *DNS : Edit* sur la seule zone `charly-hue.fr` (section 1) | `AGENDO_CLOUD_CLOUDFLARE_TOKEN_FILE` |

L'image tourne sous l'utilisateur 65534 : les fichiers doivent lui être lisibles.

## 4. Clé de signature

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

## 5. Variables d'environnement

Obligatoires sauf mention. Aucun domaine ni seuil n'a de valeur par défaut dans le code.

| Variable | Exemple | Rôle |
|---|---|---|
| `AGENDO_CLOUD_LISTEN` | `0.0.0.0:8080` (défaut de l'image) | adresse d'écoute |
| `AGENDO_CLOUD_DATABASE_URL_FILE` | `/run/secrets/database-url` | URL de la base (fichier) |
| `AGENDO_CLOUD_API_URL` | `https://agendo-api.charly-hue.fr` | API des maisons ; `iss` des jetons |
| `AGENDO_CLOUD_PORTAL_URL` | `https://agendo-account.charly-hue.fr` | portail : origine WebAuthn, RP ID (son hôte), liens des e-mails |
| `AGENDO_CLOUD_ZONE` | `agendo.charly-hue.fr` | `ZONE_MAISONS` : les maisons sont `<16 base32>.ZONE` |
| `AGENDO_CLOUD_RELAYS` | `tls://agendo-relay-1.charly-hue.fr` | relais SNI annoncés, séparés par des virgules |
| `AGENDO_CLOUD_PUSH_URLS` | `https://agendo-push-1.charly-hue.fr` | relais push (URL de base), séparés par des virgules |
| `AGENDO_CLOUD_SIGNING_KEY_FILE` | `/run/secrets/signing-key` | graine de la clé de signature (fichier) |
| `AGENDO_CLOUD_SIGNING_KID` | `k1` | identifiant de la clé courante |
| `AGENDO_CLOUD_PUBLISHED_KEYS` | `k0=…` | facultatif : anciennes clés encore publiées (rotation) |
| `AGENDO_CLOUD_MAILER` | `resend` | `resend`, ou `outbox` en développement |
| `AGENDO_CLOUD_MAIL_FROM` | `Agendo Access <ne-pas-repondre@charly-hue.fr>` | expéditeur (domaine vérifié chez Resend ; adresse à adapter) |
| `AGENDO_CLOUD_RESEND_API_KEY_FILE` | `/run/secrets/resend-api-key` | clé Resend (fichier) |
| `AGENDO_CLOUD_RESEND_API_URL` | — | facultatif : `https://api.resend.com` par défaut |
| `AGENDO_CLOUD_OUTBOX_DIR` | `/tmp/outbox` | avec `outbox` seulement : un fichier par e-mail |
| `AGENDO_CLOUD_DNS` | `cloudflare` | `cloudflare`, ou `fake` en développement (rien n'est publié) |
| `AGENDO_CLOUD_CLOUDFLARE_ZONE_ID` | `023e1…` | identifiant de la zone Cloudflare qui contient `ZONE_MAISONS` (V1 : `charly-hue.fr`) |
| `AGENDO_CLOUD_CLOUDFLARE_TOKEN_FILE` | `/run/secrets/dns-token` | jeton d'API *DNS : Edit* sur cette seule zone (fichier) |
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

## 6. Traefik

Deux domaines sur l'application (Dokploy → *Domains*), port 8080, HTTPS par Let's Encrypt :
`agendo-api.charly-hue.fr` et `agendo-account.charly-hue.fr`. Le portail exige HTTPS (cookie `__Host-`, WebAuthn).
Le bilan de santé de l'image (`HEALTHCHECK`) appelle `agendo-access-cloud healthcheck`
(`GET /healthz`, qui interroge la base).

## 7. Administration

Dans le terminal Dokploy de l'application (même environnement et mêmes fichiers que `serve`) :

```sh
agendo-access-cloud admin invite personne@exemple.fr   # compte invité, lien de 7 jours par e-mail
agendo-access-cloud admin list
agendo-access-cloud admin suspend personne@exemple.fr  # jetons refusés : subscription_inactive
agendo-access-cloud admin resume personne@exemple.fr
agendo-access-cloud admin revoke-house <hôte ou étiquette>
```

Relancer `invite` sur un compte encore invité renvoie un nouveau lien (l'ancien cesse de valoir).

## 8. Sauvegardes

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

## 9. Image et CI

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

### Socle et clé de déploiement (dépôt privé)

Le protocole et WebAuthn viennent de `charlyhue/agendo` (privé), par SSH, à un tag publié :

```toml
agendo-access-protocol = { git = "ssh://git@github.com/charlyhue/agendo.git", tag = "v0.42.0" }
agendo-webauthn = { git = "ssh://git@github.com/charlyhue/agendo.git", tag = "v0.42.0" }
```

`.cargo/config.toml` (`[net] git-fetch-with-cli = true`, et `CARGO_NET_GIT_FETCH_WITH_CLI` en
CI et dans l'image) fait passer cargo par `git` et `ssh` : en local, l'agent SSH et
`~/.ssh/config` de la personne suffisent ; en CI et dans l'image, une clé de déploiement en
lecture :

1. Créez une paire de clés dédiée, sans phrase de passe :
   `ssh-keygen -t ed25519 -N "" -C "agendo-access-cloud CI" -f agendo-deploy`.
2. `charlyhue/agendo` → *Settings* → *Deploy keys* → *Add deploy key* : collez
   `agendo-deploy.pub`, **sans** « Allow write access ».
3. `charlyhue/agendo-access-cloud` → secret Actions `AGENDO_DEPLOY_KEY` : collez le contenu de
   `agendo-deploy` (clé privée), puis effacez les deux fichiers locaux.

La CI charge la clé dans l'agent (`webfactory/ssh-agent`, qui ajoute aussi les clés d'hôte de
GitHub) ; l'image la reçoit par `docker build --ssh default`.

**Monter de version du socle** : changer le tag dans `Cargo.toml` (les deux lignes), puis
`cargo update -p agendo-access-protocol -p agendo-webauthn`, tests, clippy et
`cargo deny check` (les avis de sécurité ignorés dans `deny.toml` peuvent ne plus avoir lieu
d'être). La spec qui fait foi est celle du tag :
`git -C /Users/chue/workspace/agendo show v0.42.0:docs/superpowers/specs/2026-11-04-agendo-access-design.md`.

### Construire l'image à la main

```sh
# Depuis GitHub (clé de l'agent SSH, en lecture sur charlyhue/agendo) :
docker build --ssh default -t agendo-access-cloud .
# Sans GitHub, depuis le dépôt local du socle (qui doit contenir le tag) :
git clone --bare /Users/chue/workspace/agendo /tmp/agendo.git
docker build --build-context agendo=/tmp/agendo.git --build-arg AGENDO_GIT=file:///agendo -t agendo-access-cloud .
```

## 10. Développement local

```sh
scripts/test.sh                         # PostgreSQL de test en conteneur + cargo test
```

Pour lancer le serveur à la main : une base (par exemple `scripts/db.sh up`, puis une base
créée dedans), un fichier pour son URL, `keygen` pour la clé, `AGENDO_CLOUD_MAILER=outbox`
(les e-mails arrivent en fichiers), `AGENDO_CLOUD_DNS=fake`,
`AGENDO_CLOUD_PORTAL_URL=http://localhost:<port>` (le HTTP n'est accepté que sur la boucle
locale), les seuils ci-dessus, puis `cargo run -- migrate` et `cargo run -- serve`.
