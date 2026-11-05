(function installPhase3ConsoleAuth(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.Phase3ConsoleAuth = api;
})(typeof globalThis === "undefined" ? this : globalThis, function createPhase3ConsoleAuth() {
  "use strict";

  // Invite-only sign-in for the deployed console: Cognito Hosted UI with the
  // authorization-code flow and PKCE (S256). The console is a public client,
  // so it holds no client secret. Only the ID token is kept, in session
  // storage, and it is dropped on expiry, on a 401, or on sign-out. No refresh
  // token is stored. The API re-verifies every token server-side; the checks
  // here only stop the console from sending or showing a token it should not.

  const STORAGE_KEY = "vorrin-console-session";
  const PENDING_KEY = "vorrin-console-sign-in";
  const CLOCK_SKEW_SECONDS = 60;
  const HOSTED_UI = /^https:\/\/[a-z0-9-]+\.auth\.[a-z0-9-]+\.amazoncognito\.com$/;
  const CLIENT_ID = /^[a-z0-9]{1,128}$/;

  function validateConfig(value, origin) {
    if (!value || typeof value !== "object" || value.mode !== "invite_only") return null;
    const { clientId, hostedUiUrl, redirectUri, scopes } = value;
    if (typeof clientId !== "string" || !CLIENT_ID.test(clientId)) return null;
    if (typeof hostedUiUrl !== "string" || !HOSTED_UI.test(hostedUiUrl)) return null;
    if (typeof redirectUri !== "string") return null;
    let redirect;
    try {
      redirect = new URL(redirectUri);
    } catch (_error) {
      return null;
    }
    // The callback must return to this exact console, never another origin.
    if (redirect.protocol !== "https:" || redirect.origin !== origin || redirect.search || redirect.hash) return null;
    if (!Array.isArray(scopes) || !scopes.includes("openid") || scopes.some((scope) => !/^[a-z]+$/.test(scope))) return null;
    return { clientId, hostedUiUrl, redirectUri: redirect.href, scopes: [...scopes] };
  }

  function base64UrlEncode(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    const encoded = typeof btoa === "function" ? btoa(binary) : Buffer.from(binary, "binary").toString("base64");
    return encoded.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function base64UrlDecode(text) {
    if (typeof text !== "string" || !/^[A-Za-z0-9_-]+$/.test(text)) throw new Error("invalid base64url");
    const padded = text.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(text.length / 4) * 4, "=");
    const binary = typeof atob === "function" ? atob(padded) : Buffer.from(padded, "base64").toString("binary");
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  }

  function randomToken(cryptoImpl, byteLength = 32) {
    const bytes = new Uint8Array(byteLength);
    cryptoImpl.getRandomValues(bytes);
    return base64UrlEncode(bytes);
  }

  async function createPkcePair(cryptoImpl) {
    if (!cryptoImpl || typeof cryptoImpl.getRandomValues !== "function" || !cryptoImpl.subtle) {
      throw new Error("secure random and SubtleCrypto are required for sign-in");
    }
    const verifier = randomToken(cryptoImpl, 32);
    const digest = await cryptoImpl.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    return { verifier, challenge: base64UrlEncode(new Uint8Array(digest)) };
  }

  function buildAuthorizeUrl(config, { state, nonce, challenge }) {
    const url = new URL("/oauth2/authorize", config.hostedUiUrl);
    url.search = new URLSearchParams({
      response_type: "code",
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      scope: config.scopes.join(" "),
      state,
      nonce,
      code_challenge: challenge,
      code_challenge_method: "S256",
    }).toString();
    return url.href;
  }

  function buildLogoutUrl(config) {
    const url = new URL("/logout", config.hostedUiUrl);
    url.search = new URLSearchParams({ client_id: config.clientId, logout_uri: config.redirectUri }).toString();
    return url.href;
  }

  function parseCallback(href) {
    const url = new URL(href);
    const params = url.searchParams;
    if (params.has("error")) return { error: params.get("error") || "sign_in_failed" };
    const code = params.get("code");
    const state = params.get("state");
    if (!code && !state) return null;
    if (!code || !state || !/^[A-Za-z0-9_-]{1,2048}$/.test(code)) return { error: "invalid_callback" };
    return { code, state };
  }

  function decodeJwtPayload(token) {
    if (typeof token !== "string") throw new Error("token missing");
    const parts = token.split(".");
    if (parts.length !== 3) throw new Error("token is not a JWT");
    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[1])));
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("token payload invalid");
    return payload;
  }

  function issuerFor(config) {
    // Hosted UI: https://<prefix>.auth.<region>.amazoncognito.com. The ID token issuer is the
    // user pool URL, which the console cannot know from the domain alone, so only the host
    // family is checked here; the API authorizer and Lambda verify the exact issuer.
    const region = new URL(config.hostedUiUrl).hostname.split(".")[2];
    return new RegExp(`^https://cognito-idp\\.${region}\\.amazonaws\\.com/${region}_[A-Za-z0-9]+$`);
  }

  function validateIdToken(token, config, { nonce, nowSeconds }) {
    let claims;
    try {
      claims = decodeJwtPayload(token);
    } catch (_error) {
      return null;
    }
    if (
      claims.token_use !== "id" ||
      claims.aud !== config.clientId ||
      typeof claims.iss !== "string" ||
      !issuerFor(config).test(claims.iss) ||
      (nonce !== undefined && claims.nonce !== nonce) ||
      !Number.isFinite(claims.exp) ||
      claims.exp <= nowSeconds + CLOCK_SKEW_SECONDS ||
      typeof claims.sub !== "string"
    ) {
      return null;
    }
    return { idToken: token, expiresAt: claims.exp, email: typeof claims.email === "string" ? claims.email : "" };
  }

  function readJson(storage, key) {
    try {
      const raw = storage.getItem(key);
      return raw ? JSON.parse(raw) : null;
    } catch (_error) {
      return null;
    }
  }

  function writeJson(storage, key, value) {
    try {
      if (value === null) storage.removeItem(key);
      else storage.setItem(key, JSON.stringify(value));
    } catch (_error) {
      // Without session storage the user signs in again after a reload.
    }
  }

  function createSession({ config, storage, cryptoImpl, fetchImpl, location, history, now = () => Date.now() }) {
    let session = null;
    const nowSeconds = () => Math.floor(now() / 1000);

    function load() {
      const saved = readJson(storage, STORAGE_KEY);
      session = saved && typeof saved.idToken === "string" ? validateIdToken(saved.idToken, config, { nowSeconds: nowSeconds() }) : null;
      if (!session) writeJson(storage, STORAGE_KEY, null);
      return session;
    }

    function current() {
      if (session && session.expiresAt <= nowSeconds() + CLOCK_SKEW_SECONDS) signOutLocally();
      return session;
    }

    function signOutLocally() {
      session = null;
      writeJson(storage, STORAGE_KEY, null);
    }

    async function signIn() {
      const { verifier, challenge } = await createPkcePair(cryptoImpl);
      const state = randomToken(cryptoImpl, 24);
      const nonce = randomToken(cryptoImpl, 24);
      writeJson(storage, PENDING_KEY, { state, nonce, verifier, createdAt: now() });
      location.assign(buildAuthorizeUrl(config, { state, nonce, challenge }));
    }

    function signOut() {
      signOutLocally();
      location.assign(buildLogoutUrl(config));
    }

    async function completeSignIn() {
      const callback = parseCallback(location.href);
      if (!callback) return { status: "none" };
      const pending = readJson(storage, PENDING_KEY);
      writeJson(storage, PENDING_KEY, null);
      // Remove the one-time code and state from the address bar and history.
      history.replaceState(null, "", config.redirectUri);
      if (callback.error) return { status: "error", reason: callback.error };
      if (
        !pending ||
        typeof pending.state !== "string" ||
        pending.state !== callback.state ||
        typeof pending.verifier !== "string" ||
        !Number.isFinite(pending.createdAt) ||
        now() - pending.createdAt > 10 * 60 * 1000
      ) {
        return { status: "error", reason: "state_mismatch" };
      }
      const response = await fetchImpl(new URL("/oauth2/token", config.hostedUiUrl).href, {
        method: "POST",
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
        referrerPolicy: "no-referrer",
        headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: config.clientId,
          code: callback.code,
          redirect_uri: config.redirectUri,
          code_verifier: pending.verifier,
        }).toString(),
      });
      if (!response.ok) return { status: "error", reason: "token_exchange_failed" };
      const tokens = await response.json();
      const verified = validateIdToken(tokens && tokens.id_token, config, { nonce: pending.nonce, nowSeconds: nowSeconds() });
      if (!verified) return { status: "error", reason: "invalid_id_token" };
      session = verified;
      writeJson(storage, STORAGE_KEY, { idToken: verified.idToken });
      return { status: "signed_in" };
    }

    function authorizationHeaders() {
      const active = current();
      return active ? { Authorization: `Bearer ${active.idToken}` } : {};
    }

    return { load, current, signIn, signOut, signOutLocally, completeSignIn, authorizationHeaders };
  }

  return {
    STORAGE_KEY,
    PENDING_KEY,
    validateConfig,
    base64UrlEncode,
    createPkcePair,
    buildAuthorizeUrl,
    buildLogoutUrl,
    parseCallback,
    decodeJwtPayload,
    validateIdToken,
    createSession,
  };
});
