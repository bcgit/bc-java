package org.bouncycastle.openpgp.operator;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyUtils;
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
    protected final KeyFingerPrintCalculator fingerPrintCalculator;

    /**
     * Create an instance of the key pair generator.
     *
     * @param version      public key version ({@link org.bouncycastle.bcpg.PublicKeyPacket#VERSION_4}
     *                     or {@link org.bouncycastle.bcpg.PublicKeyPacket#VERSION_6}).
     * @param creationTime key creation time
     * @param random       secure random number generator
     */
    public PGPKeyPairGenerator(int version,
                               Date creationTime,
                               SecureRandom random,
                               KeyFingerPrintCalculator fingerPrintCalculator)
    {
        this.creationTime = new Date((creationTime.getTime() / 1000) * 1000);
        this.version = version;
        this.random = random;
        this.fingerPrintCalculator = fingerPrintCalculator;
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
        return generateX25519KeyPair().asSubkey(fingerPrintCalculator);
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
        return generateEd25519KeyPair().asSubkey(fingerPrintCalculator);
    }

    /**
     * Generate a RSA key pair with the given bit-strength.
     * It is recommended to use at least 2048 bits or more.
     * The key will be generated over the default exponent {@code 65537}.
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
     * @param exponent    RSA exponent {@code e}
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
     * @return Ed25519 key pair
     * @throws PGPException if the key pair cannot be generated
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-public-key-algorithms">
     * RFC9580 - Public Key Algorithms</a>
     */
    public abstract PGPKeyPair generateEd25519KeyPair()
        throws PGPException;

    /**
     * Generate an elliptic curve signing key over the twisted Edwards curve448.
     * The key will use {@link PublicKeyAlgorithmTags#Ed448} which was introduced with RFC9580.
     *
     * @return Ed448 signing key pair
     * @throws PGPException if the key pair cannot be generated
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-public-key-algorithms">
     * RFC9580 - Public Key Algorithms</a>
     */
    public abstract PGPKeyPair generateEd448KeyPair()
        throws PGPException;

    /**
     * Generate an elliptic curve Diffie-Hellman encryption key over curve25519.
     * THe key will use {@link PublicKeyAlgorithmTags#X25519} which was introduced with RFC9580.
     * For legacy X25519 keys use {@link #generateLegacyX25519KeyPair()} instead.
     *
     * @return X25519 encryption key pair
     * @throws PGPException if the key pair cannot be generated
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-public-key-algorithms">
     * RFC9580 - Public Key Algorithms</a>
     */
    public abstract PGPKeyPair generateX25519KeyPair()
        throws PGPException;

    /**
     * Generate an elliptic curve Diffie-Hellman encryption key over curve448.
     * THe key will use {@link PublicKeyAlgorithmTags#X448} which was introduced with RFC9580.
     *
     * @return X448 encryption key pair
     * @throws PGPException if the key pair cannot be generated
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-public-key-algorithms">
     * RFC9580 - Public Key Algorithms</a>
     */
    public abstract PGPKeyPair generateX448KeyPair()
        throws PGPException;

    /**
     * Generate a legacy elliptic curve signing key pair over the twisted Edwards curve25519.
     * Legacy keys have good application support, but MUST NOT be used as OpenPGP v6 keys.
     * The key will use {@link PublicKeyAlgorithmTags#EDDSA_LEGACY} as algorithm ID.
     * For OpenPGP v6 (RFC9580) use {@link #generateEd25519KeyPair()} instead.
     *
     * @return legacy Ed25519 key pair
     * @throws PGPException if the key pair cannot be generated
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-koch-eddsa-for-openpgp-04">
     * Legacy Draft: EdDSA for OpenPGP</a>
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

    /**
     * Generate an ECDH elliptic curve encryption key over the NIST p-256 curve.
     * {@code NIST P-256} is equivalent to {@code prime256v1} and {@code secp256r1}.
     *
     * @return NIST p-256 ECDSA encryption key pair
     * @throws PGPException if the key pair cannot be generated
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc6637.html">
     *     RFC6637 - Elliptic Curve Cryptography in OpenPGP</a>
     */
    public PGPKeyPair generateNistP256ECDHKeyPair()
        throws PGPException
    {
        return generateECDHKeyPair(SECObjectIdentifiers.secp256r1);
    }

    /**
     * Generate an ECDH elliptic curve encryption key over the NIST p-384 curve.
     * {@code NIST P-384} is equivalent to {@code secp384r1}.
     *
     * @return NIST p-384 ECDSA encryption key pair
     * @throws PGPException if the key pair cannot be generated
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc6637.html">
     *     RFC6637 - Elliptic Curve Cryptography in OpenPGP</a>
     */
    public PGPKeyPair generateNistP384ECDHKeyPair()
        throws PGPException
    {
        return generateECDHKeyPair(SECObjectIdentifiers.secp384r1);
    }

    /**
     * Generate an ECDH elliptic curve encryption key over the NIST p-521 curve.
     * {@code NIST P-521} is equivalent to {@code secp521r1}.
     *
     * @return NIST p-521 ECDSA encryption key pair
     * @throws PGPException if the key pair cannot be generated
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc6637.html">
     *     RFC6637 - Elliptic Curve Cryptography in OpenPGP</a>
     */
    public PGPKeyPair generateNistP521ECDHKeyPair()
        throws PGPException
    {
        return generateECDHKeyPair(SECObjectIdentifiers.secp521r1);
    }

    /**
     * Generate an ECDH elliptic curve encryption key over the brainpoolP256r1 curve.
     *
     * @return BrainpoolP256r1 ECDH encryption key pair
     * @throws PGPException if the key pair cannot be generated
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-ecc-curves-for-openpgp">
     *     RFC9580 - ECC Curves for OpenPGP</a>
     */
    public PGPKeyPair generateBrainpoolP256r1ECDHKeyPair()
            throws PGPException
    {
        return generateECDHKeyPair(TeleTrusTObjectIdentifiers.brainpoolP256r1);
    }

    /**
     * Generate an ECDH elliptic curve encryption key over the brainpoolP384r1 curve.
     *
     * @return BrainpoolP384r1 ECDH encryption key pair
     * @throws PGPException if the key pair cannot be generated
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-ecc-curves-for-openpgp">
     *     RFC9580 - ECC Curves for OpenPGP</a>
     */
    public PGPKeyPair generateBrainpoolP384r1ECDHKeyPair()
            throws PGPException
    {
        return generateECDHKeyPair(TeleTrusTObjectIdentifiers.brainpoolP384r1);
    }

    /**
     * Generate an ECDH elliptic curve encryption key over the brainpoolP512r1 curve.
     *
     * @return BrainpoolP512r1 ECDH encryption key pair
     * @throws PGPException if the key pair cannot be generated
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-ecc-curves-for-openpgp">
     *     RFC9580 - ECC Curves for OpenPGP</a>
     */
    public PGPKeyPair generateBrainpoolP512r1ECDHKeyPair()
            throws PGPException
    {
        return generateECDHKeyPair(TeleTrusTObjectIdentifiers.brainpoolP512r1);
    }

    /**
     * Generate an ECDSA elliptic curve signing key over the NIST p-256 curve.
     * {@code NIST P-256} is equivalent to {@code prime256v1} and {@code secp256r1}.
     *
     * @return NIST p-256 ECDSA signing key pair
     * @throws PGPException if the key pair cannot be generated
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc6637.html">
     *     RFC6637 - Elliptic Curve Cryptography in OpenPGP</a>
     */
    public PGPKeyPair generateNistP256ECDSAKeyPair()
        throws PGPException
    {
        return generateECDSAKeyPair(SECObjectIdentifiers.secp256r1);
    }

    /**
     * Generate an ECDSA elliptic curve signing key over the NIST p-384 curve.
     * {@code NIST P-384} is equivalent to {@code secp384r1}.
     *
     * @return NIST p-384 ECDSA signing key pair
     * @throws PGPException if the key pair cannot be generated
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc6637.html">
     *     RFC6637 - Elliptic Curve Cryptography in OpenPGP</a>
     */
    public PGPKeyPair generateNistP384ECDSAKeyPair()
        throws PGPException
    {
        return generateECDSAKeyPair(SECObjectIdentifiers.secp384r1);
    }

    /**
     * Generate an ECDSA elliptic curve signing key over the NIST p-521 curve.
     * {@code NIST P-521} is equivalent to {@code secp521r1}.
     *
     * @return NIST p-521 ECDSA signing key pair
     * @throws PGPException if the key pair cannot be generated
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc6637.html">
     *     RFC6637 - Elliptic Curve Cryptography in OpenPGP</a>
     */
    public PGPKeyPair generateNistP521ECDSAKeyPair()
        throws PGPException
    {
        return generateECDSAKeyPair(SECObjectIdentifiers.secp521r1);
    }

    /**
     * Generate an ECDSA elliptic curve signing key over the brainpoolP256r1 curve.
     *
     * @return BrainpoolP256r1 ECDSA signing key pair
     * @throws PGPException if the key pair cannot be generated
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-ecc-curves-for-openpgp">
     *     RFC9580 - ECC Curves for OpenPGP</a>
     */
    public PGPKeyPair generateBrainpoolP256r1ECDSAKeyPair()
            throws PGPException
    {
        return generateECDSAKeyPair(TeleTrusTObjectIdentifiers.brainpoolP256r1);
    }

    /**
     * Generate an ECDSA elliptic curve signing key over the brainpoolP384r1 curve.
     *
     * @return BrainpoolP384r1 ECDSA signing key pair
     * @throws PGPException if the key pair cannot be generated
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-ecc-curves-for-openpgp">
     *     RFC9580 - ECC Curves for OpenPGP</a>
     */
    public PGPKeyPair generateBrainpoolP384r1ECDSAKeyPair()
            throws PGPException
    {
        return generateECDSAKeyPair(TeleTrusTObjectIdentifiers.brainpoolP384r1);
    }

    /**
     * Generate an ECDSA elliptic curve signing key over the brainpoolP512r1 curve.
     *
     * @return BrainpoolP512r1 ECDSA signing key pair
     * @throws PGPException if the key pair cannot be generated
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-ecc-curves-for-openpgp">
     *     RFC9580 - ECC Curves for OpenPGP</a>
     */
    public PGPKeyPair generateBrainpoolP512r1ECDSAKeyPair()
            throws PGPException
    {
        return generateECDSAKeyPair(TeleTrusTObjectIdentifiers.brainpoolP512r1);
    }

    /**
     * Generate an ML-DSA-65 + Ed25519 composite signing key pair
     * ({@link PublicKeyAlgorithmTags#MLDSA65_Ed25519}, RFC 9980 sec. 5). The two component keys are generated
     * independently, as RFC 9980 sec. 5.2.1 requires. Only version 6 keys may use this algorithm.
     *
     * @return ML-DSA-65 + Ed25519 key pair
     * @throws PGPException if the key pair cannot be generated, or the generator is for a key version other than 6
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-5">
     * RFC 9980 - Composite Signature Schemes</a>
     */
    public PGPKeyPair generateMLDSA65Ed25519KeyPair()
        throws PGPException
    {
        throw new PGPException("ML-DSA-65 + Ed25519 key pair generation is not supported by this generator");
    }

    /**
     * Generate an ML-DSA-87 + Ed448 composite signing key pair
     * ({@link PublicKeyAlgorithmTags#MLDSA87_Ed448}, RFC 9980 sec. 5). The two component keys are generated
     * independently, as RFC 9980 sec. 5.2.1 requires. Only version 6 keys may use this algorithm.
     *
     * @return ML-DSA-87 + Ed448 key pair
     * @throws PGPException if the key pair cannot be generated, or the generator is for a key version other than 6
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-5">
     * RFC 9980 - Composite Signature Schemes</a>
     */
    public PGPKeyPair generateMLDSA87Ed448KeyPair()
        throws PGPException
    {
        throw new PGPException("ML-DSA-87 + Ed448 key pair generation is not supported by this generator");
    }

    /**
     * Generate an SLH-DSA-SHAKE-128s signing key pair ({@link PublicKeyAlgorithmTags#SLHDSA_SHAKE_128s},
     * RFC 9980 sec. 6). Only version 6 keys may use this algorithm.
     *
     * @return SLH-DSA-SHAKE-128s key pair
     * @throws PGPException if the key pair cannot be generated, or the generator is for a key version other than 6
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-6">
     * RFC 9980 - SLH-DSA</a>
     */
    public PGPKeyPair generateSLHDSAShake128sKeyPair()
        throws PGPException
    {
        throw new PGPException("SLH-DSA-SHAKE-128s key pair generation is not supported by this generator");
    }

    /**
     * Generate an SLH-DSA-SHAKE-128f signing key pair ({@link PublicKeyAlgorithmTags#SLHDSA_SHAKE_128f},
     * RFC 9980 sec. 6). Only version 6 keys may use this algorithm.
     *
     * @return SLH-DSA-SHAKE-128f key pair
     * @throws PGPException if the key pair cannot be generated, or the generator is for a key version other than 6
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-6">
     * RFC 9980 - SLH-DSA</a>
     */
    public PGPKeyPair generateSLHDSAShake128fKeyPair()
        throws PGPException
    {
        throw new PGPException("SLH-DSA-SHAKE-128f key pair generation is not supported by this generator");
    }

    /**
     * Generate an SLH-DSA-SHAKE-256s signing key pair ({@link PublicKeyAlgorithmTags#SLHDSA_SHAKE_256s},
     * RFC 9980 sec. 6). Only version 6 keys may use this algorithm.
     *
     * @return SLH-DSA-SHAKE-256s key pair
     * @throws PGPException if the key pair cannot be generated, or the generator is for a key version other than 6
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-6">
     * RFC 9980 - SLH-DSA</a>
     */
    public PGPKeyPair generateSLHDSAShake256sKeyPair()
        throws PGPException
    {
        throw new PGPException("SLH-DSA-SHAKE-256s key pair generation is not supported by this generator");
    }

    /**
     * Generate an ML-KEM-768 + X25519 composite encryption key pair
     * ({@link PublicKeyAlgorithmTags#MLKEM768_X25519}, RFC 9980 sec. 4). The two component keys are generated
     * independently, as RFC 9980 sec. 4.2.2 requires. The algorithm may be used with version 6 keys and, as the
     * single exception among the PQ(/T) algorithms, with version 4 encryption subkeys.
     *
     * @return ML-KEM-768 + X25519 key pair
     * @throws PGPException if the key pair cannot be generated, or the generator is for a key version other than 4 or 6
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-4">
     * RFC 9980 - Composite KEM Schemes</a>
     */
    public PGPKeyPair generateMLKEM768X25519KeyPair()
        throws PGPException
    {
        throw new PGPException("ML-KEM-768 + X25519 key pair generation is not supported by this generator");
    }

    /**
     * Generate an ML-KEM-1024 + X448 composite encryption key pair
     * ({@link PublicKeyAlgorithmTags#MLKEM1024_X448}, RFC 9980 sec. 4). The two component keys are generated
     * independently, as RFC 9980 sec. 4.2.2 requires. Only version 6 keys may use this algorithm.
     *
     * @return ML-KEM-1024 + X448 key pair
     * @throws PGPException if the key pair cannot be generated, or the generator is for a key version other than 6
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9980.html#section-4">
     * RFC 9980 - Composite KEM Schemes</a>
     */
    public PGPKeyPair generateMLKEM1024X448KeyPair()
        throws PGPException
    {
        throw new PGPException("ML-KEM-1024 + X448 key pair generation is not supported by this generator");
    }

    /**
     * Check that the generator's key version may carry the given RFC 9980 algorithm (sec. 3.5).
     *
     * @param algorithm public key algorithm ID
     * @throws PGPException if the key version is not permitted for the algorithm
     */
    protected void checkPQCKeyVersion(int algorithm)
        throws PGPException
    {
        if (!PublicKeyUtils.isAlgorithmAllowedForKeyVersion(algorithm, version))
        {
            throw new PGPException("An implementation MUST NOT generate a version " + version
                + " key with public key algorithm " + algorithm + " (RFC 9980 sec. 3.5).");
        }
    }

    /**
     * Generate an elliptic curve Diffie-Hellman encryption key pair over the curve identified by the given OID.
     *
     * @param curveOID OID of the elliptic curve
     * @return PGP key pair
     * @throws PGPException if the key pair cannot be generated
     */
    public abstract PGPKeyPair generateECDHKeyPair(ASN1ObjectIdentifier curveOID)
        throws PGPException;

    /**
     * Generate an elliptic curve signing key over the curve identified by the given OID.
     *
     * @param curveOID OID of the elliptic curve
     * @return PGP key pair
     * @throws PGPException if the key pair cannot be generated
     */
    public abstract PGPKeyPair generateECDSAKeyPair(ASN1ObjectIdentifier curveOID)
        throws PGPException;
}
