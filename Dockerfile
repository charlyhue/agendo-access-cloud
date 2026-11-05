# Image du plan de contrôle : cargo-chef (cache des dépendances), binaire musl statique, image
# `scratch` (le binaire, les certificats CA, rien d'autre ; utilisateur sans droits).
#
# Le socle (agendo-access-protocol, agendo-webauthn) vient de GitHub par SSH, à un tag
# (Cargo.toml) : la clé de déploiement passe par l'agent SSH (`docker build --ssh default`).
# Essai local sans GitHub (docs/deploy.md) : AGENDO_GIT renvoie l'URL GitHub vers un clone nu
# monté par `--build-context agendo=…` :
#   git clone --bare /Users/chue/workspace/agendo /tmp/agendo.git
#   docker build --build-context agendo=/tmp/agendo.git --build-arg AGENDO_GIT=file:///agendo .

ARG CHEF_IMAGE=lukemathwalker/cargo-chef:latest-rust-alpine

# Dépôt du socle monté pour l'essai local ; vide par défaut (remplacé par `--build-context agendo=…`).
FROM scratch AS agendo

FROM ${CHEF_IMAGE} AS chef
RUN apk add --no-cache ca-certificates gcc git musl-dev openssh-client
WORKDIR /app
ARG AGENDO_GIT=
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
# Clé d'hôte publiée par GitHub (pas de confiance au premier contact).
RUN if [ -n "${AGENDO_GIT}" ]; then \
      git config --global url."${AGENDO_GIT}".insteadOf "ssh://git@github.com/charlyhue/agendo.git"; \
    fi \
 && git config --global --add safe.directory '*' \
 && mkdir -p -m 0700 /root/.ssh \
 && echo "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl" > /root/.ssh/known_hosts

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN --mount=type=ssh --mount=type=bind,from=agendo,target=/agendo \
    cargo chef cook --release --locked --recipe-path recipe.json
COPY . .
RUN --mount=type=ssh --mount=type=bind,from=agendo,target=/agendo \
    cargo build --release --locked --bin agendo-access-cloud \
 && cp target/release/agendo-access-cloud /agendo-access-cloud \
 && ! ldd /agendo-access-cloud 2>/dev/null | grep -q '=>'

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /agendo-access-cloud /agendo-access-cloud
ENV AGENDO_CLOUD_LISTEN=0.0.0.0:8080 \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
USER 65534:65534
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD ["/agendo-access-cloud", "healthcheck"]
ENTRYPOINT ["/agendo-access-cloud"]
CMD ["serve"]
