#!/usr/bin/env node
/*
 * webauthn.js - a virtual authenticator for the suite: a software passkey
 * (P-256/ES256) that produces exactly the JSON, base64url and CBOR shapes
 * a browser feeds /api/passkeys/*. Real authenticators are hardware this
 * test rig cannot assume, so the WebAuthn verification path is driven by
 * building the ceremony outputs byte by byte - which is also the only way
 * to produce *bad* ones (wrong origin, tampered signature, regressing
 * counter) on demand.
 *
 *   webauthn.js register <options.json> <state.json> <out.json> \
 *                       [--origin=URL] [--counter=N] [--bad-origin=URL] \
 *                       [--bad-challenge] [--rp=RPID] [--cross-origin]
 *     -> reads POST /api/passkeys/register/start, writes the `credential`
 *        object for /finish, parks the private key in <state.json>.
 *
 *   webauthn.js assert <options.json> <state.json> <out.json> \
 *                      [--origin=URL] [--counter=N] [--no-userhandle] \
 *                      [--bad-origin=URL] [--bad-challenge] [--bad-sig] \
 *                      [--rp=RPID] [--cross-origin]
 *     -> reads POST /api/passkeys/login/start, writes the `credential`
 *        object for /finish and advances the stored signature counter.
 *
 * `--origin` is what the clientDataJSON claims; the suite passes the base
 * URL it talks to. The rpId is taken from the server's own options unless
 * `--rp` overrides it (that override is how the rpId-hash check is fed a
 * credential from a foreign domain).
 *
 * The state file holds only base64 key bytes plus the counter - a test
 * fixture, deleted with the run.
 */
"use strict";

const fs = require("fs");
const crypto = require("node:crypto");

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

function writeJson(p, v) {
  fs.writeFileSync(p, JSON.stringify(v));
}

// base64url without padding - what the browsers' toJSON() emits.
function b64u(buf) {
  return Buffer.from(buf).toString("base64url");
}

function unb64u(s) {
  return Buffer.from(s, "base64url");
}

// ---------------------------------------------------------------------------
// Minimal CBOR writer: integers, text, byte strings, and maps (an array of
// [key, value] pairs - this authenticator never needs CBOR arrays, so an
// array in a value position *is* a map).
// ---------------------------------------------------------------------------

function cborHead(major, n) {
  if (n < 24) return [(major << 5) | n];
  if (n < 0x100) return [(major << 5) | 24, n];
  if (n < 0x10000) return [(major << 5) | 25, (n >> 8) & 0xff, n & 0xff];
  throw new Error("cbor: length out of range");
}

function cbor(v) {
  if (v instanceof Uint8Array) {
    return [...cborHead(2, v.length), ...v];
  }
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new Error("cbor: only integers");
    return v >= 0 ? cborHead(0, v) : cborHead(1, -1 - v);
  }
  if (typeof v === "string") {
    const bytes = Buffer.from(v, "utf8");
    return [...cborHead(3, bytes.length), ...bytes];
  }
  if (Array.isArray(v)) {
    const out = cborHead(5, v.length);
    for (const [k, val] of v) out.push(...cbor(k), ...cbor(val));
    return out;
  }
  throw new Error("cbor: unsupported value");
}

// ---------------------------------------------------------------------------
// authenticatorData and the ceremony payloads
// ---------------------------------------------------------------------------

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest();
}

// rpIdHash(32) || flags(1) || counter(4, big-endian), then - with the AT
// flag - aaguid(16 zeros, fmt "none" has none), credential id length
// (2, big-endian), the credential id, and the COSE public key.
function authData(rpId, flags, counter, attested) {
  const head = Buffer.alloc(37);
  sha256(Buffer.from(rpId, "utf8")).copy(head, 0);
  head[32] = flags & 0xff;
  head.writeUInt32BE(counter >>> 0, 33);
  if (!attested) return head;
  const aaguid = Buffer.alloc(16);
  const len = Buffer.alloc(2);
  len.writeUInt16BE(attested.credId.length, 0);
  return Buffer.concat([head, aaguid, len, attested.credId, Buffer.from(attested.cose)]);
}

// COSE_Key for the credential: EC2 (1:2), P-256 (-1:1), ES256 (3:-7),
// x/y as 32-byte strings pulled from the exported public JWK.
function coseKey(publicKey) {
  const jwk = publicKey.export({ format: "jwk" });
  return Uint8Array.from(
    cbor([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, unb64u(jwk.x)],
      [-3, unb64u(jwk.y)],
    ])
  );
}

// {fmt: "none", attStmt: {}, authData: bytes}
function attestationObject(rpId, flags, counter, credId, cose) {
  const auth = authData(rpId, flags, counter, { credId, cose });
  return Uint8Array.from(
    cbor([
      ["fmt", "none"],
      ["attStmt", []],
      ["authData", auth],
    ])
  );
}

// The exact bytes the authenticator hashes into the signature: a JSON
// object whose fields the server checks one by one.
function clientDataBytes(type, challenge, origin, crossOrigin) {
  return Buffer.from(
    JSON.stringify({ type, challenge, origin, crossOrigin }),
    "utf8"
  );
}

function parseArgs(rest) {
  const flags = {};
  const pos = [];
  for (const a of rest) {
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq === -1) flags[a.slice(2)] = true;
      else flags[a.slice(2, eq)] = a.slice(eq + 1);
    } else {
      pos.push(a);
    }
  }
  return { flags, pos };
}

function requireOrigin(flags) {
  if (typeof flags.origin !== "string" || !flags.origin) {
    throw new Error("--origin=URL is required (what clientDataJSON claims)");
  }
  return flags.origin;
}

// clientData fields shared by both ceremonies: the tampering flags swap in
// the exact wrong values the negative checks are about.
function buildClientData(flags, options, type) {
  const origin = flags["bad-origin"] || requireOrigin(flags);
  const challenge =
    typeof flags["bad-challenge"] === "string"
      ? flags["bad-challenge"]
      : flags["bad-challenge"]
        ? "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        : options.challenge;
  const crossOrigin = Boolean(flags["cross-origin"]);
  return clientDataBytes(type, challenge, origin, crossOrigin);
}

function usage(code) {
  console.error("usage: webauthn.js register|assert <options.json> <state.json> <out.json> [--flags]");
  process.exit(code);
}

function cmdRegister(flags, pos) {
  const [optsPath, statePath, outPath] = pos;
  if (!optsPath) usage(2);
  const options = readJson(optsPath);
  const rpId = flags.rp || (options.rp && options.rp.id);
  if (!rpId) throw new Error("registration options carry no rp.id");
  const counter = Number.parseInt(flags.counter || "0", 10);

  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const credId = flags["cred-id"] ? unb64u(flags["cred-id"]) : crypto.randomBytes(32);
  const cose = coseKey(publicKey);
  const cd = buildClientData(flags, options, "webauthn.create");
  // UP (0x01) | UV (0x04) | AT (0x40): present, verified, attested data.
  const att = attestationObject(rpId, flagsUpUvAt(), counter, credId, cose);

  const credential = {
    id: b64u(credId),
    rawId: b64u(credId),
    type: "public-key",
    authenticatorAttachment: "cross-platform",
    response: {
      clientDataJSON: b64u(cd),
      attestationObject: b64u(att),
      transports: ["usb"],
    },
  };
  writeJson(outPath, credential);
  writeJson(statePath, {
    privateKey: b64u(privateKey.export({ type: "pkcs8", format: "der" })),
    credentialId: b64u(credId),
    // What /register/start put into user.id; assertions may echo it as
    // userHandle the way a browser does.
    userHandle: (options.user && options.user.id) || null,
    counter,
  });
}

function flagsUpUvAt() {
  return 0x01 | 0x04 | 0x40;
}

function cmdAssert(flags, pos) {
  const [optsPath, statePath, outPath] = pos;
  if (!optsPath) usage(2);
  const options = readJson(optsPath);
  const state = readJson(statePath);
  const rpId = flags.rp || options.rpId;
  if (!rpId) throw new Error("assertion options carry no rpId");
  const counter = flags.counter
    ? Number.parseInt(flags.counter, 10)
    : state.counter + 1;

  const cd = buildClientData(flags, options, "webauthn.get");
  // UP (0x01) | UV (0x04): present and verified; no attested data here.
  const auth = authData(rpId, 0x01 | 0x04, counter, null);
  const privateKey = crypto.createPrivateKey({
    key: unb64u(state.privateKey),
    format: "der",
    type: "pkcs8",
  });
  // Sign(authenticatorData || SHA256(clientDataJSON)); node's sign() hashes
  // with SHA-256 itself, matching the server's Verifier::verify.
  const message = Buffer.concat([auth, sha256(cd)]);
  let sig = crypto.sign("sha256", message, privateKey);
  if (flags["bad-sig"]) {
    sig = Buffer.from(sig);
    sig[sig.length - 1] ^= 0xff;
  }

  const credential = {
    id: state.credentialId,
    rawId: state.credentialId,
    type: "public-key",
    authenticatorAttachment: "cross-platform",
    response: {
      clientDataJSON: b64u(cd),
      authenticatorData: b64u(auth),
      signature: b64u(sig),
      userHandle: flags["no-userhandle"]
        ? null
        : flags["bad-userhandle"]
          ? b64u(Buffer.alloc(8)) // valid base64url, wrong account id
          : state.userHandle,
    },
  };
  writeJson(outPath, credential);
  // Advance the counter like a real device would, so a later assertion
  // starts from the value the server last saw.
  state.counter = counter;
  writeJson(statePath, state);
}

function main() {
  const [, , cmd, ...rest] = process.argv;
  const { flags, pos } = parseArgs(rest);
  if (cmd === "register") cmdRegister(flags, pos);
  else if (cmd === "assert") cmdAssert(flags, pos);
  else usage(cmd === undefined ? 2 : 1);
}

try {
  main();
} catch (e) {
  console.error("webauthn.js: " + e.message);
  process.exit(1);
}
