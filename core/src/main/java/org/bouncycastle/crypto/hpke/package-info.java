/**
 * Hybrid Public Key Encryption (HPKE) per
 * <a href="https://www.rfc-editor.org/rfc/rfc9180.html">RFC 9180</a>.
 * <p>
 * HPKE composes a Key Encapsulation Mechanism (KEM), a Key Derivation Function
 * (KDF) and an Authenticated-Encryption-with-Additional-Data (AEAD) algorithm
 * into a single hybrid public-key encryption scheme. It's the building block
 * underneath MLS (RFC 9420), TLS Encrypted Client Hello, and Oblivious HTTP
 * (RFC 9458).
 *
 * <h2>Supported parameter sets</h2>
 *
 * The top-level facade {@link org.bouncycastle.crypto.hpke.HPKE} exposes the
 * full RFC 9180 algorithm matrix via {@code short} ID constants:
 *
 * <ul>
 *   <li><b>Modes</b>: {@code mode_base}, {@code mode_psk}, {@code mode_auth},
 *       {@code mode_auth_psk}.</li>
 *   <li><b>KEMs</b>: DHKEM(P-256, HKDF-SHA256), DHKEM(P-384, HKDF-SHA384),
 *       DHKEM(P-521, HKDF-SHA512), DHKEM(X25519, HKDF-SHA256),
 *       DHKEM(X448, HKDF-SHA512). External KEM implementations may be plugged
 *       in via the {@link org.bouncycastle.crypto.hpke.KEM} abstract base and
 *       the {@code HPKE(mode, kemId, kdfId, aeadId, KEM, encSize)} constructor.</li>
 *   <li><b>KDFs</b>: HKDF-SHA256, HKDF-SHA384, HKDF-SHA512.</li>
 *   <li><b>AEADs</b>: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, and the
 *       export-only sentinel (id 0xFFFF) for callers who only need
 *       {@link org.bouncycastle.crypto.hpke.HPKEContext#export(byte[], int)}
 *       and not seal/open.</li>
 * </ul>
 *
 * <h2>Typical caller flow (mode_base)</h2>
 *
 * <p>Sender:</p>
 * <pre>
 * HPKE hpke = new HPKE(HPKE.mode_base,
 *                      HPKE.kem_X25519_SHA256,
 *                      HPKE.kdf_HKDF_SHA256,
 *                      HPKE.aead_AES_GCM128);
 * HPKEContextWithEncapsulation ctx = hpke.setupBaseS(recipientPub, info);
 * byte[] enc = ctx.getEncapsulation();          // transmit alongside ct
 * byte[] ct  = ctx.seal(aad, plaintext);        // ctx is stateful, advances nonce
 * </pre>
 *
 * <p>Receiver:</p>
 * <pre>
 * HPKEContext ctx = hpke.setupBaseR(enc, recipientKeyPair, info);
 * byte[] pt = ctx.open(aad, ct);
 * </pre>
 *
 * <p>For single-message use cases the {@link org.bouncycastle.crypto.hpke.HPKE#seal}
 * and {@link org.bouncycastle.crypto.hpke.HPKE#open} convenience methods do both
 * steps in one call and return {@code [enc, ct]} / the plaintext respectively.</p>
 *
 * <h2>Sealing semantics</h2>
 *
 * The contexts returned by {@code setup*S} and {@code setup*R} are stateful:
 * each {@code seal} / {@code open} call advances an internal sequence number
 * that's XOR-mixed into the AEAD nonce, so a single context can encrypt or
 * decrypt many messages in order without nonce reuse. The
 * {@link org.bouncycastle.crypto.hpke.HPKEContextWithEncapsulation#getEncapsulation}
 * method returns the {@code enc} octet string that must be transmitted alongside
 * the first ciphertext so the receiver can run the matching {@code setup*R}.
 */
package org.bouncycastle.crypto.hpke;
