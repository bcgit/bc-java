package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;

public abstract class PGPKeyPairGenerator
{

    protected final Date creationTime;
    protected final int version;
    protected SecureRandom random;

    /**
     * Create an instance of the key pair generator.
     *
     * @param version public key version ({@link org.bouncycastle.bcpg.PublicKeyPacket#VERSION_4}
     *               or {@link org.bouncycastle.bcpg.PublicKeyPacket#VERSION_6}).
     * @param creationTime key creation time
     * @param random secure random number generator
     */
    public PGPKeyPairGenerator(int version, Date creationTime, SecureRandom random)
    {
        this.creationTime = new Date((creationTime.getTime() / 1000) * 1000);
        this.version = version;
        this.random = random;
    }

    /**
     * Generate a primary key.
     * A primary key MUST use a signing-capable public key algorithm.
     *
     * @return primary key pair
     * @throws PGPException if the key pair cannot be generated
     */
    public PGPKeyPair generatePrimaryKey()
            throws PGPException
    {
        return generateEd25519KeyPair();
    }

    /**
     * Generate an encryption subkey.
     * An encryption subkey MUST use an encryption-capable public key algorithm.
     *
     * @return encryption subkey pair
     * @throws PGPException if the key pair cannot be generated
     */
    public PGPKeyPair generateEncryptionSubkey()
            throws PGPException
    {
        return generateX25519KeyPair();
    }

    /**
     * Generate a signing subkey.
     * A signing subkey MUST use a signing-capable public key algorithm.
     *
     * @return signing subkey pair
     * @throws PGPException if the key pair cannot be generated
     */
    public PGPKeyPair generateSigningSubkey()
            throws PGPException
    {
        return generateEd25519KeyPair();
    }

    /**
     * Generate a RSA key pair with the given bit-strength.
     * It is recommended to use at least 2048 bits or more.
     * The key will be generated over the default exponent <pre>65537</pre>.
     * RSA keys are deprecated for OpenPGP v6.
     *
     * @param bitStrength strength of the key pair in bits
     * @return rsa key pair
     * @throws PGPException if the key pair cannot be generated
     */
    public PGPKeyPair generateRsaKeyPair(int bitStrength)
            throws PGPException
    {
        return generateRsaKeyPair(BigInteger.valueOf(0x10001), bitStrength);
    }

    /**
     * Generate a RSA key pair with the given bit-strength over a custom exponent.
     * It is recommended to use at least 2048 bits or more.
     * RSA keys are deprecated for OpenPGP v6.
     *
     * @param exponent RSA exponent <pre>e</pre>
     * @param bitStrength strength of the key pair in bits
     * @return rsa key pair
     * @throws PGPException if the key pair cannot be generated
     */
    public abstract PGPKeyPair generateRsaKeyPair(BigInteger exponent, int bitStrength)
            throws PGPException;

    /**
     * Generate an elliptic curve signing key over the twisted Edwards curve25519.
     * The key will use {@link PublicKeyAlgorithmTags#Ed25519} which was introduced with RFC9580.
     * For legacy Ed25519 keys use {@link #generateLegacyEd25519KeyPair()}.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-public-key-algorithms">
     *     RFC9580 - Public Key Algorithms</a>
     * @return Ed25519 key pair
     * @throws PGPException if the key pair cannot be generated
     */
    public abstract PGPKeyPair generateEd25519KeyPair()
            throws PGPException;

    /**
     * Generate an elliptic curve signing key over the twisted Edwards curve448.
     * The key will use {@link PublicKeyAlgorithmTags#Ed448} which was introduced with RFC9580.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-public-key-algorithms">
     *     RFC9580 - Public Key Algorithms</a>
     * @return Ed448 signing key pair
     * @throws PGPException if the key pair cannot be generated
     */
    public abstract PGPKeyPair generateEd448KeyPair()
            throws PGPException;

    /**
     * Generate an elliptic curve Diffie-Hellman encryption key over curve25519.
     * THe key will use {@link PublicKeyAlgorithmTags#X25519} which was introduced with RFC9580.
     * For legacy X25519 keys use {@link #generateLegacyX25519KeyPair()} instead.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-public-key-algorithms">
     *     RFC9580 - Public Key Algorithms</a>
     * @return X25519 encryption key pair
     * @throws PGPException if the key pair cannot be generated
     */
    public abstract PGPKeyPair generateX25519KeyPair()
            throws PGPException;

    /**
     * Generate an elliptic curve Diffie-Hellman encryption key over curve448.
     * THe key will use {@link PublicKeyAlgorithmTags#X448} which was introduced with RFC9580.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-public-key-algorithms">
     *     RFC9580 - Public Key Algorithms</a>
     * @return X448 encryption key pair
     * @throws PGPException if the key pair cannot be generated
     */
    public abstract PGPKeyPair generateX448KeyPair()
            throws PGPException;

    /**
     * Generate a legacy elliptic curve signing key pair over the twisted Edwards curve25519.
     * Legacy keys have good application support, but MUST NOT be used as OpenPGP v6 keys.
     * The key will use {@link PublicKeyAlgorithmTags#EDDSA_LEGACY} as algorithm ID.
     * For OpenPGP v6 (RFC9580) use {@link #generateEd25519KeyPair()} instead.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-koch-eddsa-for-openpgp-04">
     *     Legacy Draft: EdDSA for OpenPGP</a>
     * @return legacy Ed25519 key pair
     * @throws PGPException if the key pair cannot be generated
     */
    public abstract PGPKeyPair generateLegacyEd25519KeyPair()
            throws PGPException;

    /**
     * Generate a legacy elliptic curve Diffie-Hellman encryption key pair over curve25519.
     * Legacy keys have good application support, but MUST NOT be used as OpenPGP v6 keys.
     * The key will use {@link PublicKeyAlgorithmTags#ECDH} as algorithm ID.
     * For OpenPGP v6 (RFC9580) use {@link #generateX25519KeyPair()} instead.
     *
     * @return legacy X25519 key pair
     * @throws PGPException if the key pair cannot be generated
     */
    public abstract PGPKeyPair generateLegacyX25519KeyPair()
            throws PGPException;
}
