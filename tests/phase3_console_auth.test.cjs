const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");

const auth = require("../scripts/console/auth.js");

const ORIGIN = "https://d111111abcdef8.cloudfront.net";
const RAW_CONFIG = {
  mode: "invite_only",
  clientId: "4ab5c6d7e8f9g0h1i2j3k4l5m6",
  hostedUiUrl: "https://vorrin-console.auth.us-east-1.amazoncognito.com",
  redirectUri: `${ORIGIN}/`,
  scopes: ["openid", "email"],
};
const CONFIG = auth.validateConfig(RAW_CONFIG, ORIGIN);
const ISSUER = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEf123";
const NOW_MS = Date.UTC(2026, 10, 5, 12, 0, 0);
const NOW_S = Math.floor(NOW_MS / 1000);

function b64url(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function jwt(claims) {
  return `${b64url({ alg: "RS256", kid: "k" })}.${b64url(claims)}.signature`;
}

function idToken(overrides = {}) {
  return jwt({
    sub: "1f2e3d4c-5b6a-4789-8abc-def012345678",
    aud: CONFIG.clientId,
    iss: ISSUER,
    token_use: "id",
    exp: NOW_S + 3600,
    email: "invitee@example.com",
    ...overrides,
  });
}

function memoryStorage() {
  const values = new Map();
  return {
    values,
    getItem: (key) => (values.has(key) ? values.get(key) : null),
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: (key) => values.delete(key),
  };
}

function harness({ href = `${ORIGIN}/`, tokenResponse, now = NOW_MS } = {}) {
  const storage = memoryStorage();
  const calls = { assign: [], replace: [], fetch: [] };
  const location = { href, assign: (url) => calls.assign.push(url) };
  const history = { replaceState: (_state, _title, url) => calls.replace.push(url) };
  const fetchImpl = async (url, init) => {
    calls.fetch.push({ url, init });
    const body = typeof tokenResponse === "function" ? tokenResponse(init) : tokenResponse;
    return { ok: body !== undefined, json: async () => body };
  };
  const session = auth.createSession({
    config: CONFIG,
    storage,
    cryptoImpl: crypto.webcrypto,
    fetchImpl,
    location,
    history,
    now: () => now,
  });
  return { session, storage, calls, location };
}

// ------------------------------------------------------------------ config --

test("a valid invite-only config is accepted and normalized", () => {
  assert.deepEqual(CONFIG, {
    clientId: RAW_CONFIG.clientId,
    hostedUiUrl: RAW_CONFIG.hostedUiUrl,
    redirectUri: `${ORIGIN}/`,
    scopes: ["openid", "email"],
  });
});

for (const [name, change] of [
  ["public mode", { mode: "public" }],
  ["redirect to another origin", { redirectUri: "https://attacker.example/" }],
  ["plain HTTP redirect", { redirectUri: `${ORIGIN.replace("https", "http")}/` }],
  ["redirect with a query", { redirectUri: `${ORIGIN}/?next=/x` }],
  ["non-Cognito hosted UI", { hostedUiUrl: "https://login.attacker.example" }],
  ["hosted UI with a path", { hostedUiUrl: `${RAW_CONFIG.hostedUiUrl}/login` }],
  ["malformed client ID", { clientId: "client id" }],
  ["scopes without openid", { scopes: ["email"] }],
  ["unexpected scope characters", { scopes: ["openid", "aws.cognito.signin.user.admin"] }],
]) {
  test(`config is rejected: ${name}`, () => {
    assert.equal(auth.validateConfig({ ...RAW_CONFIG, ...change }, ORIGIN), null);
  });
}

test("config is rejected when it is not an object", () => {
  assert.equal(auth.validateConfig(null, ORIGIN), null);
  assert.equal(auth.validateConfig("invite_only", ORIGIN), null);
});

// -------------------------------------------------------------------- PKCE --

test("PKCE challenge is the base64url SHA-256 of a high-entropy verifier", async () => {
  const { verifier, challenge } = await auth.createPkcePair(crypto.webcrypto);

  assert.match(verifier, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(challenge, crypto.createHash("sha256").update(verifier).digest("base64url"));
  const second = await auth.createPkcePair(crypto.webcrypto);
  assert.notEqual(second.verifier, verifier);
});

test("PKCE refuses to run without secure randomness", async () => {
  await assert.rejects(auth.createPkcePair({}), /secure random/);
});

test("the authorize URL uses the code flow with S256, state, and nonce", () => {
  const url = new URL(auth.buildAuthorizeUrl(CONFIG, { state: "s1", nonce: "n1", challenge: "c1" }));

  assert.equal(url.origin + url.pathname, `${RAW_CONFIG.hostedUiUrl}/oauth2/authorize`);
  assert.deepEqual(Object.fromEntries(url.searchParams), {
    response_type: "code",
    client_id: CONFIG.clientId,
    redirect_uri: `${ORIGIN}/`,
    scope: "openid email",
    state: "s1",
    nonce: "n1",
    code_challenge: "c1",
    code_challenge_method: "S256",
  });
});

test("the logout URL returns to the console", () => {
  const url = new URL(auth.buildLogoutUrl(CONFIG));

  assert.equal(url.pathname, "/logout");
  assert.equal(url.searchParams.get("logout_uri"), `${ORIGIN}/`);
  assert.equal(url.searchParams.get("client_id"), CONFIG.clientId);
});

test("callbacks are parsed strictly", () => {
  assert.equal(auth.parseCallback(`${ORIGIN}/`), null);
  assert.deepEqual(auth.parseCallback(`${ORIGIN}/?code=abc-123&state=s1`), { code: "abc-123", state: "s1" });
  assert.deepEqual(auth.parseCallback(`${ORIGIN}/?error=access_denied`), { error: "access_denied" });
  assert.deepEqual(auth.parseCallback(`${ORIGIN}/?code=abc`), { error: "invalid_callback" });
  assert.deepEqual(auth.parseCallback(`${ORIGIN}/?code=<script>&state=s1`), { error: "invalid_callback" });
});

// ---------------------------------------------------------------- ID token --

test("a valid ID token is accepted", () => {
  const verified = auth.validateIdToken(idToken({ nonce: "n1" }), CONFIG, { nonce: "n1", nowSeconds: NOW_S });

  assert.equal(verified.email, "invitee@example.com");
  assert.equal(verified.expiresAt, NOW_S + 3600);
});

for (const [name, token, options] of [
  ["another client's token", idToken({ aud: "someotherclient" }), {}],
  ["an access token", idToken({ token_use: "access" }), {}],
  ["an expired token", idToken({ exp: NOW_S - 1 }), {}],
  ["a token expiring within the clock skew", idToken({ exp: NOW_S + 30 }), {}],
  ["a token from another region", idToken({ iss: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_AbCdEf123" }), {}],
  ["a token from a non-Cognito issuer", idToken({ iss: "https://attacker.example/us-east-1_AbCdEf123" }), {}],
  ["a nonce mismatch", idToken({ nonce: "other" }), { nonce: "n1" }],
  ["a missing nonce", idToken(), { nonce: "n1" }],
  ["a token without a subject", idToken({ sub: undefined }), {}],
  ["a malformed token", "not.a-jwt", {}],
  ["a non-string token", undefined, {}],
]) {
  test(`ID token is rejected: ${name}`, () => {
    assert.equal(auth.validateIdToken(token, CONFIG, { nowSeconds: NOW_S, ...options }), null);
  });
}

// ----------------------------------------------------------------- session --

async function signInAndReturn(tokenResponse) {
  const first = harness();
  await first.session.signIn();
  const authorize = new URL(first.calls.assign[0]);
  const state = authorize.searchParams.get("state");
  const nonce = authorize.searchParams.get("nonce");
  const second = harness({
    href: `${ORIGIN}/?code=auth-code-1&state=${state}`,
    tokenResponse: tokenResponse ? tokenResponse(nonce) : { id_token: idToken({ nonce }) },
  });
  for (const [key, value] of first.storage.values) second.storage.setItem(key, value);
  return { first, second, state, nonce, authorize };
}

test("sign-in stores only a pending state and redirects to the hosted UI", async () => {
  const { session, storage, calls } = harness();

  await session.signIn();

  assert.equal(calls.assign.length, 1);
  assert.ok(calls.assign[0].startsWith(`${RAW_CONFIG.hostedUiUrl}/oauth2/authorize?`));
  const pending = JSON.parse(storage.getItem(auth.PENDING_KEY));
  assert.deepEqual(Object.keys(pending).sort(), ["createdAt", "nonce", "state", "verifier"]);
  assert.equal(storage.getItem(auth.STORAGE_KEY), null);
});

test("a matching callback exchanges the code with PKCE and no client secret", async () => {
  const { second, authorize } = await signInAndReturn();

  const result = await second.session.completeSignIn();

  assert.deepEqual(result, { status: "signed_in" });
  assert.equal(second.calls.fetch.length, 1);
  const { url, init } = second.calls.fetch[0];
  assert.equal(url, `${RAW_CONFIG.hostedUiUrl}/oauth2/token`);
  assert.equal(init.method, "POST");
  assert.equal(init.credentials, "omit");
  const body = new URLSearchParams(init.body);
  assert.equal(body.get("grant_type"), "authorization_code");
  assert.equal(body.get("code"), "auth-code-1");
  assert.equal(body.get("redirect_uri"), `${ORIGIN}/`);
  assert.equal(body.has("client_secret"), false);
  assert.equal(
    crypto.createHash("sha256").update(body.get("code_verifier")).digest("base64url"),
    authorize.searchParams.get("code_challenge"),
  );
  assert.deepEqual(second.calls.replace, [`${ORIGIN}/`]);
  assert.equal(second.storage.getItem(auth.PENDING_KEY), null);
  assert.match(second.session.authorizationHeaders().Authorization, /^Bearer [^.]+\.[^.]+\.[^.]+$/);
});

test("a callback with a forged state never contacts the token endpoint", async () => {
  const { first } = await signInAndReturn();
  const forged = harness({ href: `${ORIGIN}/?code=auth-code-1&state=forged`, tokenResponse: { id_token: idToken() } });
  for (const [key, value] of first.storage.values) forged.storage.setItem(key, value);

  assert.deepEqual(await forged.session.completeSignIn(), { status: "error", reason: "state_mismatch" });
  assert.equal(forged.calls.fetch.length, 0);
  assert.deepEqual(forged.session.authorizationHeaders(), {});
});

test("a callback cannot be replayed after the pending sign-in is consumed", async () => {
  const { second } = await signInAndReturn();
  await second.session.completeSignIn();
  second.session.signOutLocally();

  assert.deepEqual(await second.session.completeSignIn(), { status: "error", reason: "state_mismatch" });
  assert.equal(second.calls.fetch.length, 1);
});

test("a pending sign-in older than ten minutes is rejected", async () => {
  const { first, state } = await signInAndReturn();
  const late = harness({
    href: `${ORIGIN}/?code=auth-code-1&state=${state}`,
    tokenResponse: { id_token: idToken() },
    now: NOW_MS + 11 * 60 * 1000,
  });
  for (const [key, value] of first.storage.values) late.storage.setItem(key, value);

  assert.deepEqual(await late.session.completeSignIn(), { status: "error", reason: "state_mismatch" });
  assert.equal(late.calls.fetch.length, 0);
});

test("an ID token with the wrong nonce is not stored", async () => {
  const { second } = await signInAndReturn(() => ({ id_token: idToken({ nonce: "replayed" }) }));

  assert.deepEqual(await second.session.completeSignIn(), { status: "error", reason: "invalid_id_token" });
  assert.equal(second.storage.getItem(auth.STORAGE_KEY), null);
  assert.deepEqual(second.session.authorizationHeaders(), {});
});

test("a failed token exchange is reported without storing anything", async () => {
  const { second } = await signInAndReturn(() => undefined);

  assert.deepEqual(await second.session.completeSignIn(), { status: "error", reason: "token_exchange_failed" });
  assert.equal(second.storage.getItem(auth.STORAGE_KEY), null);
});

test("a provider error on the callback clears the address bar", async () => {
  const { session, calls } = harness({ href: `${ORIGIN}/?error=access_denied&state=s1` });

  assert.deepEqual(await session.completeSignIn(), { status: "error", reason: "access_denied" });
  assert.deepEqual(calls.replace, [`${ORIGIN}/`]);
});

test("a stored session survives a reload and is dropped once expired", async () => {
  const { second } = await signInAndReturn();
  await second.session.completeSignIn();

  const reloaded = harness();
  reloaded.storage.setItem(auth.STORAGE_KEY, second.storage.getItem(auth.STORAGE_KEY));
  assert.ok(reloaded.session.load());

  const later = harness({ now: NOW_MS + 2 * 3600 * 1000 });
  later.storage.setItem(auth.STORAGE_KEY, second.storage.getItem(auth.STORAGE_KEY));
  assert.equal(later.session.load(), null);
  assert.equal(later.storage.getItem(auth.STORAGE_KEY), null);
});

test("tampered session storage is discarded", () => {
  const { session, storage } = harness();
  storage.setItem(auth.STORAGE_KEY, JSON.stringify({ idToken: idToken({ aud: "someotherclient" }) }));

  assert.equal(session.load(), null);
  assert.equal(storage.getItem(auth.STORAGE_KEY), null);
});

test("sign-out clears the session and goes to the hosted UI logout", async () => {
  const { second } = await signInAndReturn();
  await second.session.completeSignIn();

  second.session.signOut();

  assert.equal(second.storage.getItem(auth.STORAGE_KEY), null);
  assert.deepEqual(second.session.authorizationHeaders(), {});
  assert.ok(second.calls.assign.at(-1).startsWith(`${RAW_CONFIG.hostedUiUrl}/logout?`));
});
