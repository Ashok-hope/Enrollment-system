/**
 * Client-Side Cryptographic Library
 * Implements Web Crypto API primitives (ECDSA P-256, SHA-256, AES-256-GCM)
 * Ensuring Private Keys NEVER leave the client browser!
 */

const CryptoClient = {
  // Utility: ArrayBuffer to Hex String
  buf2hex(buffer) {
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
  },

  // Utility: Hex String to Uint8Array
  hex2buf(hex) {
    if (!hex) return new Uint8Array();
    const cleanHex = hex.trim().replace(/^0x/, '');
    const bytes = new Uint8Array(Math.ceil(cleanHex.length / 2));
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16);
    }
    return bytes;
  },

  // Deterministic Canonical JSON Stringify (matching Python canonical_json)
  canonicalJson(obj) {
    if (obj === null || typeof obj !== 'object') {
      return JSON.stringify(obj);
    }
    if (Array.isArray(obj)) {
      return '[' + obj.map(item => this.canonicalJson(item)).join(',') + ']';
    }
    const sortedKeys = Object.keys(obj).sort();
    const keyVals = sortedKeys.map(k => `${JSON.stringify(k)}:${this.canonicalJson(obj[k])}`);
    return '{' + keyVals.join(',') + '}';
  },

  // SHA-256 Digest
  async sha256(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
    return this.buf2hex(hashBuffer);
  },

  // Generate ECDSA P-256 Key Pair
  async generateKeyPair() {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-256"
      },
      true,
      ["sign", "verify"]
    );

    // Export Public Key in raw uncompressed format (65 bytes: 04 + X + Y)
    const rawPub = await window.crypto.subtle.exportKey("raw", keyPair.publicKey);
    const pubKeyHex = this.buf2hex(rawPub);

    // Export Private Key in PKCS8 format
    const pkcs8 = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    const privKeyHex = this.buf2hex(pkcs8);

    // Compute permanent identity address = SHA-256(PublicKey)
    const identityAddress = await this.sha256(pubKeyHex);

    return {
      keyPair,
      publicKeyHex: pubKeyHex,
      privateKeyHex: privKeyHex,
      identityAddress: identityAddress
    };
  },

  // Sign Arbitrary String with ECDSA P-256 Private Key
  async signMessage(cryptoKeyOrHex, messageString) {
    const encoder = new TextEncoder();
    const data = encoder.encode(messageString);

    let privateKey;
    if (typeof cryptoKeyOrHex === 'string') {
      // Import from PKCS8 hex
      const pkcs8Buf = this.hex2buf(cryptoKeyOrHex);
      privateKey = await window.crypto.subtle.importKey(
        "pkcs8",
        pkcs8Buf,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign"]
      );
    } else {
      privateKey = cryptoKeyOrHex;
    }

    // Sign using SHA-256. WebCrypto outputs IEEE P1363 (64 bytes raw r||s)
    const sigBuffer = await window.crypto.subtle.sign(
      { name: "ECDSA", hash: { name: "SHA-256" } },
      privateKey,
      data
    );

    return this.buf2hex(sigBuffer);
  },

  // Encrypt Student Sensitive Payload with AES-256-GCM
  async encryptAESGCM(plaintext, keyHex = null) {
    let rawKey;
    if (keyHex) {
      rawKey = this.hex2buf(keyHex);
    } else {
      rawKey = window.crypto.getRandomValues(new Uint8Array(32)); // 256-bit
    }

    const key = await window.crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );

    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);

    const encryptedWithTag = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv, tagLength: 128 },
      key,
      data
    );

    const encryptedBytes = new Uint8Array(encryptedWithTag);
    // In WebCrypto, the last 16 bytes is the authentication tag
    const ciphertext = encryptedBytes.slice(0, encryptedBytes.length - 16);
    const tag = encryptedBytes.slice(encryptedBytes.length - 16);

    return {
      ciphertextHex: this.buf2hex(ciphertext),
      ivHex: this.buf2hex(iv),
      tagHex: this.buf2hex(tag),
      keyHex: this.buf2hex(rawKey)
    };
  }
};
