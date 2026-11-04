# Agendo Access Cloud : consignes pour l'agent

Plan de contrôle et portail d'Agendo Access. La spec fait foi :
`git -C /Users/chue/workspace/agendo show agendo-access:docs/superpowers/specs/2026-11-04-agendo-access-design.md`
(sections « Plan de contrôle », « Protocole commun », « Sécurité »). Les points marqués
**[à trancher]** se proposent à la personne, ils ne se décident pas seul : prendre le choix par
défaut indiqué, le signaler, et le lister dans la PR.

## Règles

- Tout est en français : messages de log, commentaires, docs, textes du portail, e-mails.
- Aucun secret dans le code, Git, `.env` ni les logs (clé de signature, mot de passe
  PostgreSQL, clé Resend, jeton API DNS, jetons d'invitation, codes, cookies de session). Les
  secrets arrivent par des **fichiers montés** dont le chemin est donné par une variable
  `…_FILE`.
- Configuration par variables d'environnement uniquement. **Aucun domaine en dur** (ni le
  nôtre, ni celui d'une maison) et aucun seuil anti-abus en dur : tout ce qui est propre au
  déploiement passe par la configuration (`docs/deploy.md` liste les variables).
- Le code s'écrit **comme s'il était public** : `cargo-deny` en CI, pas d'`unwrap` sur une
  donnée venue du réseau.
- Pas d'inscription publique : un compte naît d'une invitation (`admin invite`). Aucun mot de
  passe : passkey, code par e-mail en secours. Jetons d'invitation, codes et sessions sont
  **hachés** en base.
- Le compte cloud n'ouvre jamais la maison : le plan de contrôle délivre des jetons et pose
  des TXT ACME, rien d'autre. Aucun jeton de téléphone, aucun contenu de maison en base.
- Le protocole (`agendo-access-protocol`) et WebAuthn (`agendo-webauthn`) viennent du dépôt
  `agendo`, branche `agendo-access`, par Git. **Ne jamais modifier le dépôt agendo** : un besoin
  ou un désaccord sur le protocole se note dans la PR, pour la personne.
- Les skills superpowers s'invoquent avant d'agir dès qu'ils s'appliquent
  (`writing-plans`, `test-driven-development`, `verification-before-completion`).
