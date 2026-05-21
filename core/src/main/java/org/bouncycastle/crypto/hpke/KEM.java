package org.bouncycastle.crypto.hpke;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;


/**
 * Abstract base for HPKE Key Encapsulation Mechanisms per
 * <a href="https://www.rfc-editor.org/rfc/rfc9180.html#section-4">RFC 9180 &sect;4</a>.
 * <p>
 * Concrete subclass {@link DHKEM} implements the five DHKEM variants registered
 * by RFC 9180 (P-256/P-384/P-521/X25519/X448). External implementations &mdash;
 * e.g. post-quantum KEMs such as ML-KEM or the hybrid X25519+Kyber768 used by
 * MLS &mdash; can be plugged in by subclassing this class and passing the
 * instance to the {@code HPKE(mode, kemId, kdfId, aeadId, KEM, encSize)}
 * constructor; the framework only requires:
 * <ul>
 *   <li>{@code Encap} / {@code Decap} &mdash; the basic KEM encapsulate /
 *       decapsulate pair returning {@code [enc, sharedSecret]}.</li>
 *   <li>{@code Encap(pkR, kpE)} &mdash; a sender-supplied-ephemeral variant
 *       used by the OHTTP test vectors and any deterministic KAT.</li>
 *   <li>{@code AuthEncap} / {@code AuthDecap} &mdash; the authenticated variant
 *       used by {@code mode_auth} / {@code mode_auth_psk}.</li>
 *   <li>{@code GeneratePrivateKey} / {@code DeriveKeyPair(ikm)} &mdash; fresh
 *       and deterministic key generation respectively.</li>
 *   <li>{@code SerializePublicKey} / {@code DeserializePublicKey} /
 *       {@code SerializePrivateKey} / {@code DeserializePrivateKey} &mdash; the
 *       KEM-specific wire encoding.</li>
 *   <li>{@code getEncryptionSize} &mdash; the byte-length of the {@code enc}
 *       output, used by the facade to allocate space.</li>
 * </ul>
 */
public abstract class KEM
{
    // Key Generation
    abstract AsymmetricCipherKeyPair GeneratePrivateKey();
    abstract AsymmetricCipherKeyPair DeriveKeyPair(byte[] ikm);

    // Encapsulates a shared secret for a given public key and returns the encapsulated key and shared secret.
    abstract byte[][] Encap(AsymmetricKeyParameter recipientPublicKey);
    abstract byte[][] Encap(AsymmetricKeyParameter pkR, AsymmetricCipherKeyPair kpE);
    abstract byte[][] AuthEncap(AsymmetricKeyParameter pkR, AsymmetricCipherKeyPair kpS);

    // Decapsulates the given encapsulated key using the recipient's key pair and returns the shared secret.
    abstract byte[] Decap(byte[] encapsulatedKey, AsymmetricCipherKeyPair recipientKeyPair);
    abstract byte[] AuthDecap(byte[] enc, AsymmetricCipherKeyPair kpR, AsymmetricKeyParameter pkS);

    // Serialization
    abstract byte[] SerializePublicKey(AsymmetricKeyParameter publicKey);
    abstract byte[] SerializePrivateKey(AsymmetricKeyParameter key);

    // Deserialization
    abstract AsymmetricKeyParameter DeserializePublicKey(byte[] encodedPublicKey);
    abstract AsymmetricCipherKeyPair DeserializePrivateKey(byte[] skEncoded, byte[] pkEncoded);

    abstract int getEncryptionSize();

}