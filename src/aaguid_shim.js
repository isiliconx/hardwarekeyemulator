// aaguid_shim.js — rewrite the AAGUID a relying party sees in a WebAuthn
// *registration*, in the page world. No browser flags, no OS support.
//
// Why this exists: Chrome's CDP virtual authenticator reports a FIXED AAGUID
// (01020304050607080102030405060708; measured on Chrome 154/155/158 — there is
// no addVirtualAuthenticator option to change it), and kernels without
// CONFIG_INPUT_UHID cannot host the emulator as a real HID device. This shim is
// the identity fix for the browser-only path: whatever authenticator the
// browser uses, the RP reads the model you configure.
//
// Modes (window.__HKE_SHIM_MODE__, default "aaguid"):
//   aaguid — swap the 16 AAGUID bytes at authData[37:53] in a copy. Lengths
//            never change, so the rest of the CBOR object stays byte-identical.
//   none   — additionally re-encode the object as fmt "none" (attStmt removed),
//            the shape software passkeys commonly send. No attestation
//            signature exists to fail verification.
//
// Configure before this script runs: window.__HKE_AAGUID__ (hex, dashes ok).
// hold_aaguid.py and the unpacked extension both set it. Default: YubiKey 5C
// NFC fw 5.7.4+ (d7781e5d-e353-46aa-afe2-3ca49f13332a).
//
// Honest limits: in "aaguid" mode the packed attestation signature still
// belongs to the browser's original authenticator and no longer covers the
// modified authData — an RP that verifies attestation signatures against the
// presented x5c rejects (use --mode none there); an RP that chains to a pinned
// vendor root rejects in every mode, because that needs the vendor private key.
// Sign-in (assertion) ceremonies are untouched — assertions carry no AAGUID.

(function () {
  "use strict";
  if (window.__HKE_SHIM_INSTALLED__) return;
  window.__HKE_SHIM_INSTALLED__ = true;

  var TARGET = String(window.__HKE_AAGUID__ ||
                     "d7781e5d-e353-46aa-afe2-3ca49f13332a")
      .replace(/-/g, "").toLowerCase();
  var MODE = String(window.__HKE_SHIM_MODE__ || "aaguid").toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(TARGET)) {
    console.warn("[hke] aaguid shim: invalid __HKE_AAGUID__", TARGET);
    return;
  }
  var PATCH = new Uint8Array(16);
  for (var i = 0; i < 16; i++) PATCH[i] = parseInt(TARGET.substr(i * 2, 2), 16);

  // ---- minimal definite-length CBOR walk: locate the authData byte string ----
  function findAuthData(view) {
    var p = 0;
    function head() {
      if (p >= view.length) return null;
      var b = view[p], maj = b >> 5, min = b & 31, hl = 1, val = min;
      if (min === 24) { val = view[p + 1]; hl = 2; }
      else if (min === 25) { val = (view[p + 1] << 8) | view[p + 2]; hl = 3; }
      else if (min === 26) {
        val = ((view[p + 1] << 24) | (view[p + 2] << 16) |
               (view[p + 3] << 8) | view[p + 4]) >>> 0; hl = 5;
      } else if (min > 26) { return null; }   // indefinite lengths/floats: bail
      if (p + hl > view.length) return null;
      return { maj: maj, val: val, hl: hl };
    }
    function skip() {
      var h = head();
      if (!h) return false;
      p += h.hl;
      if (h.maj <= 1 || h.maj === 7) return true;      // uint/negint/simple
      if (h.maj === 2 || h.maj === 3) { p += h.val; return p <= view.length; }
      var n = (h.maj === 4) ? h.val : h.val * 2;
      for (var i = 0; i < n; i++) if (!skip()) return false;
      return true;
    }
    function readText() {
      var h = head();
      if (!h || h.maj !== 3) return null;
      var s = "";
      for (var i = 0; i < h.val; i++)
        s += String.fromCharCode(view[p + h.hl + i]);
      p += h.hl + h.val;
      return s;
    }
    var root = head();
    if (!root || root.maj !== 5) return null;          // top level must be a map
    p += root.hl;
    for (var e = 0; e < root.val; e++) {
      var key = readText();
      if (key === null) return null;
      if (key === "authData") {
        var h = head();
        if (!h || h.maj !== 2) return null;            // must be a byte string
        return { offset: p + h.hl, length: h.val };
      }
      if (!skip()) return null;
    }
    return null;
  }

  // ---- tiny CBOR encoder for the "none" re-encode (text/bytes/small maps) ----
  function encHead(major, val) {
    var min = val < 24 ? val : (val <= 0xFF ? 24 : (val <= 0xFFFF ? 25 : 26));
    if (min < 24) return new Uint8Array([(major << 5) | min]);
    if (min === 24) return new Uint8Array([(major << 5) | 24, val]);
    if (min === 25)
      return new Uint8Array([(major << 5) | 25, (val >> 8) & 0xFF, val & 0xFF]);
    return new Uint8Array([(major << 5) | 26, (val >>> 24) & 0xFF,
                           (val >>> 16) & 0xFF, (val >>> 8) & 0xFF,
                           val & 0xFF]);
  }
  function encText(s) {
    var bytes = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i) & 0xFF;
    return concat(encHead(3, s.length), bytes);
  }
  function encBytes(b) { return concat(encHead(2, b.length), b); }
  function concat(a, b) {
    var out = new Uint8Array(a.length + b.length);
    out.set(a, 0); out.set(b, a.length);
    return out;
  }
  function encodeNone(authBytes) {
    // map(3) { "fmt": "none", "authData": bytes, "attStmt": map(0) }
    var parts = [new Uint8Array([0xA3]),
                 encText("fmt"), encText("none"),
                 encText("authData"), encBytes(authBytes),
                 encText("attStmt"), new Uint8Array([0xA0])];
    var total = 0;
    for (var i = 0; i < parts.length; i++) total += parts[i].length;
    var out = new Uint8Array(total), at = 0;
    for (var j = 0; j < parts.length; j++) { out.set(parts[j], at); at += parts[j].length; }
    return out;
  }

  function aaguidAlreadyPatched(view, offset) {
    for (var i = 0; i < 16; i++) if (view[offset + i] !== PATCH[i]) return false;
    return true;
  }

  function b64url(buf) {
    var s = new Uint8Array(buf), t = "";
    for (var i = 0; i < s.length; i++) t += String.fromCharCode(s[i]);
    return btoa(t).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function patchedResponse(original, newAtt) {
    return new Proxy(original, {
      get: function (target, prop) {
        if (prop === "attestationObject") return newAtt;
        var value = Reflect.get(target, prop, target);
        return (typeof value === "function") ? value.bind(target) : value;
      }
    });
  }

  function patchedCredential(cred, newResp) {
    return new Proxy(cred, {
      get: function (target, prop) {
        if (prop === "response") return newResp;
        if (prop === "toJSON") {
          return function () {
            return {
              id: target.id,
              rawId: b64url(target.rawId),
              type: target.type,
              clientExtensionResults: target.getClientExtensionResults ?
                  target.getClientExtensionResults() : {},
              authenticatorAttachment: target.authenticatorAttachment,
              response: {
                clientDataJSON: b64url(target.response.clientDataJSON),
                attestationObject: b64url(newResp.attestationObject),
                transports: target.response.getTransports ?
                    target.response.getTransports() : []
              }
            };
          };
        }
        var value = Reflect.get(target, prop, target);
        return (typeof value === "function") ? value.bind(target) : value;
      }
    });
  }

  var nativeCreate = navigator.credentials.create.bind(navigator.credentials);
  navigator.credentials.create = function (options) {
    return nativeCreate(options).then(function (cred) {
      if (!cred || !cred.response || !cred.response.attestationObject)
        return cred;
      try {
        var src = new Uint8Array(cred.response.attestationObject);
        var loc = findAuthData(src);
        if (!loc || loc.length < 55 || loc.offset + 55 > src.length) {
          console.warn("[hke] aaguid shim: attestationObject not scannable — passthrough");
          return cred;
        }
        if (aaguidAlreadyPatched(src, loc.offset + 37)) return cred;

        var authBytes = src.slice(loc.offset, loc.offset + loc.length);
        for (var i = 0; i < 16; i++) authBytes[37 + i] = PATCH[i];

        var out;
        if (MODE === "none") {
          out = encodeNone(authBytes);
          console.info("[hke] aaguid shim: registration -> AAGUID " + TARGET +
                       ", fmt 'none'");
        } else {
          out = new Uint8Array(src);          // copy; every length unchanged
          out.set(authBytes, loc.offset);
          console.info("[hke] aaguid shim: registration AAGUID -> " + TARGET);
        }
        var newAtt = out.buffer.slice(out.byteOffset,
                                      out.byteOffset + out.byteLength);
        return patchedCredential(cred, patchedResponse(cred.response, newAtt));
      } catch (err) {
        console.warn("[hke] aaguid shim: patch failed — passthrough", err);
        return cred;
      }
    });
  };
  // navigator.credentials.get is untouched: assertions carry no AAGUID.
  window.__HKE_SHIM_TARGET__ = TARGET;
  window.__HKE_SHIM_MODE__ = MODE;
})();
