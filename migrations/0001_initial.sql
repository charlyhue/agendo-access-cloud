-- Schéma initial du plan de contrôle d'Agendo Access.
--
-- Aucun secret en clair : jetons d'invitation, codes et sessions sont hachés (SHA-256).
-- Aucun jeton de téléphone, aucun contenu de maison. Toutes les dates viennent de l'horloge
-- de l'application (jamais `now()` SQL), pour que les tests la maîtrisent.

CREATE TABLE accounts (
    id uuid PRIMARY KEY,
    -- Adresse en minuscules, sans blancs autour.
    email text NOT NULL UNIQUE,
    status text NOT NULL CHECK (status IN ('invited', 'active')),
    subscription_active boolean NOT NULL,
    subscription_source text NOT NULL CHECK (subscription_source IN ('manual')),
    -- Identifiant WebAuthn de la personne (`user.id`), aléatoire, sans lien avec l'e-mail.
    webauthn_user_id bytea NOT NULL UNIQUE,
    created_at timestamptz NOT NULL,
    activated_at timestamptz
);

CREATE TABLE invitations (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);
CREATE INDEX invitations_account ON invitations (account_id);

CREATE TABLE passkeys (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    credential_id bytea NOT NULL UNIQUE,
    -- Clé publique SPKI (DER).
    public_key bytea NOT NULL,
    algorithm bigint NOT NULL,
    sign_count bigint NOT NULL,
    backup_eligible boolean NOT NULL,
    transports text[] NOT NULL,
    name text NOT NULL,
    created_at timestamptz NOT NULL,
    last_used_at timestamptz
);
CREATE INDEX passkeys_account ON passkeys (account_id);

CREATE TABLE sessions (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    user_agent text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX sessions_account ON sessions (account_id);

CREATE TABLE email_codes (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    code_hash bytea NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    attempts integer NOT NULL DEFAULT 0,
    consumed_at timestamptz
);
CREATE INDEX email_codes_account ON email_codes (account_id);

-- Défis WebAuthn en cours (usage unique, quelques minutes) : en base pour que plusieurs
-- instances puissent servir la même cérémonie.
CREATE TABLE webauthn_challenges (
    challenge bytea PRIMARY KEY,
    purpose text NOT NULL CHECK (purpose IN ('register_invitation', 'register_account', 'login')),
    account_id uuid REFERENCES accounts (id) ON DELETE CASCADE,
    invitation_id uuid REFERENCES invitations (id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL
);

CREATE TABLE houses (
    id uuid PRIMARY KEY,
    -- NULL quand le compte a été supprimé : la ligne reste pour que l'étiquette ne soit
    -- jamais réattribuée.
    account_id uuid REFERENCES accounts (id) ON DELETE SET NULL,
    label text NOT NULL UNIQUE,
    host text NOT NULL UNIQUE,
    name text NOT NULL,
    -- Clé publique Ed25519 de la maison (base64url).
    public_key text NOT NULL UNIQUE,
    enrolled_at timestamptz NOT NULL,
    revoked_at timestamptz,
    last_token_at timestamptz
);
CREATE INDEX houses_account ON houses (account_id);

CREATE TABLE enrollment_codes (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    code_hash bytea NOT NULL UNIQUE,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    house_id uuid REFERENCES houses (id) ON DELETE SET NULL
);

-- Journal d'audit : connexions, invitations, rattachements, révocations. Jamais de secret
-- ni d'adresse e-mail dans `detail`.
CREATE TABLE audit (
    id bigserial PRIMARY KEY,
    at timestamptz NOT NULL,
    account_id uuid REFERENCES accounts (id) ON DELETE SET NULL,
    house_id uuid REFERENCES houses (id) ON DELETE SET NULL,
    event text NOT NULL,
    detail jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_account ON audit (account_id);

-- Compteurs de débit à fenêtre fixe, partagés entre instances.
CREATE TABLE rate_limits (
    key text NOT NULL,
    window_start timestamptz NOT NULL,
    count integer NOT NULL,
    PRIMARY KEY (key, window_start)
);
