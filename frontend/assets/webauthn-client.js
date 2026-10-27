/*
 * webauthn-client.js - the marshalling between the WebAuthn JSON the server
 * speaks and the byte-typed objects navigator.credentials wants, in both
 * directions.
 *
 * WebAuthn moves every byte field as base64url without padding (what the
 * browsers' own toJSON() emits), while the credential API only accepts
 * ArrayBuffers - and toJSON() itself exists only in newer engines, so the
 * field-by-field fallback is written out here too. One implementation, two
 * callers: login.js (the passkey tab on /login) and app.js (the device list
 * in Settings), so both ends of a ceremony convert identically.
 *
 * Loaded as a plain <script> before login.js / app.js; attaches to
 * window.FxWebAuthn.
 */
"use strict";

(function () {
  function b64urlToBytes(s) {
    const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
    const bin = atob(b64 + pad);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bytesToB64url(value) {
    const view = value instanceof ArrayBuffer ? new Uint8Array(value) : value;
    let bin = "";
    for (let i = 0; i < view.length; i += 1) bin += String.fromCharCode(view[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // POST /api/passkeys/register/start -> navigator.credentials.create input.
  // Only the byte fields convert; everything else passes through as issued.
  function createOptions(options) {
    return {
      rp: options.rp,
      user: {
        id: b64urlToBytes(options.user.id),
        name: options.user.name,
        displayName: options.user.displayName,
      },
      pubKeyCredParams: options.pubKeyCredParams,
      timeout: options.timeout,
      excludeCredentials: (options.excludeCredentials || []).map((c) => ({
        type: c.type,
        id: b64urlToBytes(c.id),
      })),
      authenticatorSelection: options.authenticatorSelection,
      attestation: options.attestation,
      challenge: b64urlToBytes(options.challenge),
    };
  }

  // POST /api/passkeys/login/start -> navigator.credentials.get input.
  function assertionOptions(options) {
    return {
      rpId: options.rpId,
      timeout: options.timeout,
      allowCredentials: (options.allowCredentials || []).map((c) => ({
        type: c.type,
        id: b64urlToBytes(c.id),
      })),
      userVerification: options.userVerification,
      challenge: b64urlToBytes(options.challenge),
    };
  }

  // PublicKeyCredential -> the JSON the finish endpoints take: toJSON()
  // where the engine has it, otherwise field by field. `kind` is
  // "register" (attestation response) or "assert" (assertion response) -
  // the two response shapes differ exactly where the spec says they do.
  function credentialToJson(cred, kind) {
    if (typeof cred.toJSON === "function") return cred.toJSON();
    const response =
      kind === "register"
        ? {
            clientDataJSON: bytesToB64url(cred.response.clientDataJSON),
            attestationObject: bytesToB64url(cred.response.attestationObject),
            transports: cred.response.transports,
          }
        : {
            clientDataJSON: bytesToB64url(cred.response.clientDataJSON),
            authenticatorData: bytesToB64url(cred.response.authenticatorData),
            signature: bytesToB64url(cred.response.signature),
            userHandle: cred.response.userHandle
              ? bytesToB64url(cred.response.userHandle)
              : null,
          };
    return {
      id: cred.id,
      rawId: bytesToB64url(cred.rawId),
      type: cred.type,
      response,
    };
  }

  window.FxWebAuthn = {
    createOptions: createOptions,
    assertionOptions: assertionOptions,
    credentialToJson: credentialToJson,
    b64urlToBytes: b64urlToBytes,
    bytesToB64url: bytesToB64url,
  };
})();
