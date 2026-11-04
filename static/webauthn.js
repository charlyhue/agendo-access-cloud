// Cérémonies WebAuthn du portail d'Agendo Access : le seul script des pages.
//
// Un bouton `data-webauthn="register"` ou `"login"` porte les adresses de ses deux requêtes
// (`data-options`, `data-finish`). Les options arrivent en base64url ; la réponse repart au
// format JSON attendu par le serveur (agendo-webauthn). Le champ `data-webauthn-name`, s'il
// existe, donne le nom de la passkey ; `data-webauthn-error` reçoit les messages.
(() => {
  "use strict";

  const encode = (buffer) =>
    btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  const decode = (text) => {
    const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(base64 + "=".repeat((4 - (base64.length % 4)) % 4));
    return Uint8Array.from(binary, (c) => c.charCodeAt(0)).buffer;
  };

  async function post(url, body) {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "Erreur " + response.status);
    return data;
  }

  async function register(button) {
    const options = await post(button.dataset.options);
    const publicKey = {
      ...options,
      challenge: decode(options.challenge),
      user: { ...options.user, id: decode(options.user.id) },
      excludeCredentials: (options.excludeCredentials || []).map((c) => ({ ...c, id: decode(c.id) })),
    };
    const credential = await navigator.credentials.create({ publicKey });
    const r = credential.response;
    const publicKeyDer = r.getPublicKey ? r.getPublicKey() : null;
    const nameField = document.querySelector("[data-webauthn-name]");
    return post(button.dataset.finish, {
      credential: {
        id: credential.id,
        rawId: encode(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: encode(r.clientDataJSON),
          authenticatorData: encode(r.getAuthenticatorData()),
          publicKey: publicKeyDer ? encode(publicKeyDer) : null,
          publicKeyAlgorithm: r.getPublicKeyAlgorithm(),
          transports: r.getTransports ? r.getTransports() : [],
        },
      },
      name: nameField ? nameField.value : "",
    });
  }

  async function login(button) {
    const options = await post(button.dataset.options);
    const credential = await navigator.credentials.get({
      publicKey: { ...options, challenge: decode(options.challenge), allowCredentials: [] },
    });
    const r = credential.response;
    return post(button.dataset.finish, {
      credential: {
        id: credential.id,
        rawId: encode(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: encode(r.clientDataJSON),
          authenticatorData: encode(r.authenticatorData),
          signature: encode(r.signature),
          userHandle: r.userHandle ? encode(r.userHandle) : null,
        },
      },
    });
  }

  function showError(message) {
    const box = document.querySelector("[data-webauthn-error]");
    if (!box) return;
    box.textContent = message;
    box.hidden = false;
  }

  document.querySelectorAll("[data-webauthn]").forEach((button) => {
    if (!window.PublicKeyCredential) {
      button.disabled = true;
      showError("Ce navigateur ne gère pas les passkeys.");
      return;
    }
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        const ceremony = button.dataset.webauthn === "register" ? register : login;
        const result = await ceremony(button);
        window.location.assign(result.redirect);
      } catch (error) {
        // Annulation par la personne : pas de message alarmant.
        showError(error && error.name === "NotAllowedError" ? "Opération annulée ou expirée." : error.message);
        button.disabled = false;
      }
    });
  });
})();
